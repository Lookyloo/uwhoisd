"""
A 'universal' WHOIS proxy server.
"""

import logging
import logging.config
import os.path
import re
import socket
import sys
import time

from uwhoisd import net, utils

try:
    import redis
except ImportError:
    print 'Redis module unavailable, redis cache and rate limiting unavailable'


USAGE = "Usage: %s <config>"

PORT = socket.getservbyname('whois', 'tcp')

CONFIG = """
[uwhoisd]
iface=0.0.0.0
port=4343
registry_whois=false
suffix=whois-servers.net

[overrides]

[prefixes]

[recursion_patterns]

[broken]

[ratelimit]

[redis]
"""

logger = logging.getLogger('uwhoisd')


class UWhois(object):
    """
    Universal WHOIS proxy.
    """

    __slots__ = (
        'conservative',
        'overrides',
        'prefixes',
        'recursion_patterns',
        'registry_whois',
        'suffix',
        'broken',
        'ratelimit',
        'redis',
    )

    def __init__(self):
        super(UWhois, self).__init__()
        self.suffix = None
        self.overrides = {}
        self.prefixes = {}
        self.recursion_patterns = {}
        self.broken = {}
        self.ratelimit = {}
        self.registry_whois = False
        self.conservative = ()
        self.redis = None

    def _get_dict(self, parser, section):
        """
        Pull a dictionary out of the config safely.
        """
        if parser.has_section(section):
            values = dict(
                (key, utils.decode_value(value))
                for key, value in parser.items(section))
        else:
            values = {}
        setattr(self, section, values)

    def read_config(self, parser):
        """
        Read the configuration for this object from a config file.
        """
        self.registry_whois = utils.to_bool(
            parser.get('uwhoisd', 'registry_whois'))
        self.suffix = parser.get('uwhoisd', 'suffix')
        self.conservative = [
            zone
            for zone in parser.get('uwhoisd', 'conservative').split("\n")
            if zone != '']

        for section in ('overrides', 'prefixes', 'broken'):
            self._get_dict(parser, section)

        if utils.to_bool(parser.get('ratelimit', 'enable')):
            redis_host = parser.get('ratelimit', 'host')
            redis_port = parser.getint('ratelimit', 'port')
            redis_database = parser.getint('ratelimit', 'db')
            self.redis = redis.StrictRedis(redis_host, redis_port,
                                           redis_database)
            self._get_dict(parser, 'ratelimit')

        for zone, pattern in parser.items('recursion_patterns'):
            self.recursion_patterns[zone] = re.compile(
                utils.decode_value(pattern),
                re.I)

    def get_whois_server(self, zone):
        """
        Get the WHOIS server for the given zone.
        """
        if zone in self.overrides:
            server = self.overrides[zone]
        else:
            server = zone + '.' + self.suffix
        if ':' in server:
            server, port = server.split(':', 1)
            port = int(port)
        else:
            port = PORT
        return server, port

    def get_registrar_whois_server(self, pattern, response):
        """
        Extract the registrar's WHOIS server from the registry response.
        """
        matches = pattern.search(response)
        return None if matches is None else matches.group('server')

    def get_prefix(self, server):
        """
        Gets the prefix required when querying the servers for the given zone.
        """
        return self.prefixes.get(server)

    def get_recursion_pattern(self, zone, server):
        return self.recursion_patterns.get(zone) or \
            self.recursion_patterns.get(server)

    def get_zone(self, query):
        for zone in self.conservative:
            if query.endswith('.' + zone):
                break
        else:
            if query.split('.')[-1].isdigit():
                zone = query.split('.')[0]
            elif ':' in query:
                zone = 'ipv6'
            else:
                _, zone = utils.split_fqdn(query)
        return zone

    def _run_query(self, server, port, query, prefix='', is_recursive=False):
        ratelimit_details = self.ratelimit.get(server)
        if self.redis is not None and ratelimit_details is not None:
            while self.redis.exists(server):
                logger.info("Rate limiting on %s (burst)", server)
                time.sleep(1)
            max_server = ratelimit_details.split()[1]
            max_key = server + '_max'
            while self.redis.zcard(max_key) > max_server:
                logger.info("Rate limiting on %s", server)
                self.redis.zremrangebyscore(max_key, '-inf', int(time.time()))
                time.sleep(1)
        with net.WhoisClient(server, port) as client:
            if is_recursive:
                logger.info("Recursive query to %s about %s", server, query)
            else:
                logger.info("Querying %s about %s", server, query)
            if self.redis is not None and ratelimit_details is not None:
                self.redis.zremrangebyscore(max_key, '-inf', int(time.time()))
                self.redis.setex(server, ratelimit_details.split()[0], '')
                self.redis.zadd(max_key, time.time() + 3600, query)
            if prefix is not None:
                return client.whois('{} {}'.format(prefix, query))
            else:
                return client.whois(query)

    def _thin_query(self, pattern, response, port, query):
        """
        Query a more detailled Whois server if possible.
        """
        server = self.get_registrar_whois_server(pattern, response)
        prefix = self.get_prefix(server)
        if server is not None:
            if not self.registry_whois:
                response = ""
            response += self._run_query(server, port, query, prefix, True)
        return response

    def whois(self, query):
        """
        Query the appropriate WHOIS server.
        """
        # Figure out the zone whose WHOIS server we're meant to be querying.
        zone = self.get_zone(query)
        # Query the registry's WHOIS server.
        server, port = self.get_whois_server(zone)
        prefix = self.get_prefix(server)
        response = self._run_query(server, port, query, prefix)

        # Thin registry? Query the registrar's WHOIS server.
        recursion_pattern = self.get_recursion_pattern(zone, server)
        if recursion_pattern is not None:
            response = self._thin_query(recursion_pattern, response, port,
                                        query)

        if self.broken.get(server) is not None:
            response += self.broken.get(server)
        return response


def main():
    """
    Execute the daemon.
    """
    if len(sys.argv) != 2:
        print >> sys.stderr, USAGE % os.path.basename(sys.argv[0])
        return 1

    logging.config.fileConfig(sys.argv[1])

    try:
        logger.info("Reading config file at '%s'", sys.argv[1])
        parser = utils.make_config_parser(CONFIG, sys.argv[1])

        iface = parser.get('uwhoisd', 'iface')
        port = parser.getint('uwhoisd', 'port')
        logger.info("Listen on %s:%d", iface, port)

        uwhois = UWhois()
        uwhois.read_config(parser)
        cache = utils.to_bool(parser.get('cache', 'enable'))
        redis_cache = utils.to_bool(parser.get('redis_cache', 'enable'))

        if cache:
            logger.info("Caching activated")
            cache = utils.Cache(
                max_size=parser.getint('cache', 'max_size'),
                max_age=parser.getint('cache', 'max_age'))

            def whois(query):
                """Caching wrapper around UWhois."""
                cache.evict_expired()
                if query in cache:
                    logger.info("Cache hit for %s", query)
                    response = cache[query]
                else:
                    response = uwhois.whois(query)
                    cache[query] = response
                return response
        elif redis_cache:
            logger.info("Redis caching activated")
            import redis
            redis_host = parser.get('redis_cache', 'host')
            redis_port = parser.getint('redis_cache', 'port')
            redis_database = parser.getint('redis_cache', 'db')
            redis_expire = parser.getint('redis_cache', 'expire')
            redis_cache = redis.StrictRedis(redis_host, redis_port,
                                            redis_database)

            def whois(query):
                """Redis caching wrapper around UWhois."""
                response = redis_cache.get(query)
                if response is None:
                    response = uwhois.whois(query)
                    redis_cache.setex(query, redis_expire, response)
                else:
                    logger.info("Redis cache hit for %s", query)
                return response
        else:
            logger.info("Caching deactivated")
            whois = uwhois.whois
    except Exception, ex:  # pylint: disable-msg=W0703
        print >> sys.stderr, "Could not parse config file: %s" % str(ex)
        return 1

    net.start_service(iface, port, whois)
    return 0


if __name__ == '__main__':
    sys.exit(main())
