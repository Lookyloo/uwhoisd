"""
A 'universal' WHOIS proxy server.
"""

import logging
import logging.config
import os.path
import re
import socket
import sys

from uwhoisd import net, utils


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
    )

    def __init__(self):
        super(UWhois, self).__init__()
        self.suffix = None
        self.overrides = {}
        self.prefixes = {}
        self.recursion_patterns = {}
        self.broken = {}
        self.registry_whois = False
        self.conservative = ()

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

    def get_registrar_whois_server(self, zone, response):
        """
        Extract the registrar's WHOIS server from the registry response.
        """
        matches = self.recursion_patterns[zone].search(response)
        return None if matches is None else matches.group('server')

    def get_prefix(self, server):
        """
        Gets the prefix required when querying the servers for the given zone.
        """
        return self.prefixes.get(server)

    def _thin_query(self, server_index, response, port, query):
        server = self.get_registrar_whois_server(server_index, response)
        if server is not None:
            if not self.registry_whois:
                response = ""
            with net.WhoisClient(server, port) as client:
                logger.info(
                    "Recursive query to %s about %s",
                    server, query)
                response += client.whois(query)
        return response

    def whois(self, query):
        """
        Query the appropriate WHOIS server.
        """
        # Figure out the zone whose WHOIS server we're meant to be querying.
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

        # Query the registry's WHOIS server.
        server, port = self.get_whois_server(zone)
        with net.WhoisClient(server, port) as client:
            logger.info("Querying %s about %s", server, query)
            prefix = self.get_prefix(zone)
            if len(prefix) == 0:
                prefix = self.get_prefix(server)
            response = client.whois(prefix + query)

        # Thin registry? Query the registrar's WHOIS server.
        if zone in self.recursion_patterns:
            response = self._thin_query(zone, response, port, query)
        elif server in self.recursion_patterns:
            response = self._thin_query(server, response, port, query)


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
