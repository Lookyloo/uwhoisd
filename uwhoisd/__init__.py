"""
A 'universal' WHOIS proxy server.
"""

import logging
import logging.config
import re
import socket
import sys
import time
import datetime
import configparser

from uwhoisd import net, utils

import argparse

try:
    import redis
    redis_lib = True
except ImportError:
    print('Redis module unavailable, redis cache, rate limiting and whowas unavailable')
    redis_lib = False

try:
    from Crypto.Hash import SHA256
    has_crypto = True
except ImportError:
    print('Pycrypto module unavailable, whowas unavailable')
    has_crypto = False

PORT = socket.getservbyname('whois', 'tcp')

logger = logging.getLogger('uwhoisd')


class UWhois(object):
    """
    Universal WHOIS proxy.
    """

    def __init__(self, config_path):
        parser = configparser.SafeConfigParser()
        parser.read(config_path)
        self.read_config(parser)
        self.iface = parser.get('uwhoisd', 'iface')
        self.port = parser.getint('uwhoisd', 'port')

    def _get_dict(self, parser, section):
        """
        Pull a dictionary out of the config safely.
        """
        if parser.has_section(section):
            values = dict((key, utils.decode_value(value)) for key, value in parser.items(section))
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
        self.conservative = [zone for zone in parser.get('uwhoisd', 'conservative').split("\n") if zone != '']

        for section in ('overrides', 'prefixes', 'broken'):
            self._get_dict(parser, section)

        if redis_lib and utils.to_bool(parser.get('redis_cache', 'enable')):
            logger.info("Redis caching activated")
            cache_host = parser.get('redis_cache', 'host')
            cache_port = parser.getint('redis_cache', 'port')
            cache_database = parser.getint('redis_cache', 'db')
            self.cache_expire = parser.getint('redis_cache', 'expire')
            self.redis_cache = redis.StrictRedis(cache_host, cache_port, cache_database, decode_responses=True)

        if redis_lib and utils.to_bool(parser.get('ratelimit', 'enable')):
            logger.info("Enable rate limiting.")
            redis_host = parser.get('ratelimit', 'host')
            redis_port = parser.getint('ratelimit', 'port')
            redis_database = parser.getint('ratelimit', 'db')
            self.redis_ratelimit = redis.StrictRedis(redis_host, redis_port, redis_database)
            self._get_dict(parser, 'ratelimit')

        if redis_lib and has_crypto and utils.to_bool(parser.get('whowas', 'enable')):
            logger.info("Enable WhoWas.")
            whowas_host = parser.get('whowas', 'host')
            whowas_port = parser.getint('whowas', 'port')
            whowas_database = parser.getint('whowas', 'db')
            self.redis_whowas = redis.StrictRedis(whowas_host, whowas_port, whowas_database, decode_response=True)

        self.recursion_patterns = {}
        for zone, pattern in parser.items('recursion_patterns'):
            self.recursion_patterns[zone] = re.compile(utils.decode_value(pattern), re.I)

    def get_whois_server(self, zone):
        """
        Get the WHOIS server for the given zone.
        """
        if zone in self.overrides:
            server = self.overrides[zone]
        else:
            server = '{}.{}'.format(zone, self.suffix)
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
        Gets the prefix required when querying the servers.
        """
        return self.prefixes.get(server)

    def get_recursion_pattern(self, server):
        """
        Get the recursion pattern after querying a server.
        """
        return self.recursion_patterns.get(server)

    def get_zone(self, query):
        """
        Get the zone of a query.
        """
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
        """
        Run the query against a server.
        """
        ratelimit_details = self.ratelimit.get(server)
        if self.redis_ratelimit is not None and ratelimit_details is not None:
            while self.redis_ratelimit.exists(server):
                logger.info("Rate limiting on %s (burst)", server)
                time.sleep(1)
            max_server = int(ratelimit_details.split()[1])
            max_key = server + '_max'
            while self.redis_ratelimit.zcard(max_key) > max_server:
                logger.info("Rate limiting on %s", server)
                self.redis_ratelimit.zremrangebyscore(max_key, '-inf', time.time())
                time.sleep(1)
        client = net.WhoisClient(server, port)
        if is_recursive:
            logger.info("Recursive query to %s about %s", server, query)
        else:
            logger.info("Querying %s about %s", server, query)
        if self.redis_ratelimit is not None and ratelimit_details is not None:
            self.redis_ratelimit.zremrangebyscore(max_key, '-inf', time.time())
            self.redis_ratelimit.setex(server, ratelimit_details.split()[0], '')
            self.redis_ratelimit.zadd(max_key, time.time() + 3600, query)
        if prefix is not None:
            query = '{} {}'.format(prefix, query)
        return client.whois(query)

    def _thin_query(self, pattern, response, port, query):
        """
        Query a more detailled Whois server if possible.
        """
        # FIXME: if a port is provided in the response, it is ignored.
        server = self.get_registrar_whois_server(pattern, response)
        prefix = self.get_prefix(server)
        if server is not None:
            if not self.registry_whois:
                response = ""
            elif self.page_feed:
                # A form feed character so it's possible to find the split.
                response += "\f"
            response += self._run_query(server, port, query, prefix, True)
        return response

    def whois(self, query):
        """
        Query the appropriate WHOIS server.
        """
        if self.redis_cache:
            response = self.redis_cache.get(query)
            if response:
                logger.info("Redis cache hit for %s", query)
                return response
        # Figure out the zone whose WHOIS server we're meant to be querying.
        zone = self.get_zone(query)
        # Query the registry's WHOIS server.
        server, port = self.get_whois_server(zone)
        prefix = self.get_prefix(server)
        response = self._run_query(server, port, query, prefix)
        # Thin registry? Query the registrar's WHOIS server.
        recursion_pattern = self.get_recursion_pattern(server)
        if recursion_pattern is not None:
            response = self._thin_query(recursion_pattern, response, port, query)

        if response:
            if self.redis_cache:
                self.redis_cache.setex(query, self.cache_expire, response)
            if self.redis_whowas:
                self.store_whois(query, response)
        else:
            logger.error("Empty response for %s", query)

        if self.broken.get(server) is not None:
            response += self.broken.get(server)
        return response

    def store_whois(self, domain, response):
        response_hash = SHA256.new(response.lower().encode()).hexdigest()
        if self.redis_whowas.exists(response_hash):
            return
        # only store if the value hasn't been set today.
        if self.redis_whowas.hsetnx(domain, datetime.date.today().isoformat(), response_hash):
            logger.info("Store %s in whowas.", domain)
            self.redis_whowas.set(response_hash, response)


def main():
    """
    Execute the daemon.
    """
    argparser = argparse.ArgumentParser(description='UWhois server')
    argparser.add_argument('-c', '--config', required=True, help='Path to the config file')
    args = argparser.parse_args()

    logging.config.fileConfig(args.config)

    logger.info("Reading config file at '%s'", args.config)
    uwhois = UWhois(args.config)
    net.start_service(uwhois.iface, uwhois.port, uwhois.whois)


if __name__ == '__main__':
    sys.exit(main())
