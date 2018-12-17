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
import hashlib
from .helpers import set_running, unset_running, get_socket_path

from uwhoisd import net, utils

import argparse

try:
    import redis
    redis_lib = True
except ImportError:
    print('Redis module unavailable, redis cache, rate limiting and whowas unavailable')
    redis_lib = False

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
            cache_socket = get_socket_path('cache')
            cache_database = parser.getint('redis_cache', 'db')
            self.cache_expire = parser.getint('redis_cache', 'expire')
            self.redis_cache = redis.StrictRedis(unix_socket_path=cache_socket, db=cache_database,
                                                 decode_responses=True)

        if redis_lib and utils.to_bool(parser.get('ratelimit', 'enable')):
            logger.info("Enable rate limiting.")
            cache_socket = get_socket_path('cache')
            redis_database = parser.getint('ratelimit', 'db')
            self.redis_ratelimit = redis.StrictRedis(unix_socket_path=str(cache_socket), db=redis_database)
            self._get_dict(parser, 'ratelimit')

        if redis_lib and utils.to_bool(parser.get('whowas', 'enable')):
            logger.info("Enable WhoWas.")
            whowas_socket = get_socket_path('whowas')
            whowas_database = parser.getint('whowas', 'db')
            self.redis_whowas = redis.StrictRedis(unix_socket_path=str(whowas_socket), db=whowas_database,
                                                  decode_responses=True)

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
            server = f'{zone}.{self.suffix}'
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
        if ratelimit_details:
            per_sec, per_hour = ratelimit_details.split()
            key_burst = f'{server}_burst'
            key_normal = f'{server}_normal'
        if self.redis_ratelimit is not None and ratelimit_details is not None:
            while self.redis_ratelimit.zcard(key_burst) > int(per_sec):
                # Max queries per sec reached
                logger.info(f"Rate limiting on {server} (burst)")
                time.sleep(.3)
                # Remove all the keys that are at least 1 sec old
                self.redis_ratelimit.zremrangebyscore(key_burst, '-inf', time.time() - 1)
            while self.redis_ratelimit.zcard(key_normal) > int(per_hour):
                # Max queries per hour reached
                logger.info(f"Rate limiting on {server}")
                time.sleep(1)
                # Remove all the keys that are at least 1 hour old
                self.redis_ratelimit.zremrangebyscore(key_normal, '-inf', time.time() - 3600)
        with net.WhoisClient(server, port) as client:
            if is_recursive:
                logger.info(f"Recursive query to {server} about {query}")
            else:
                logger.info(f"Querying {server} about {query}")
            if self.redis_ratelimit is not None and ratelimit_details is not None:
                pipeline = self.redis_ratelimit.pipeline(False)
                pipeline.zadd(key_burst, {query: int(time.time())})
                pipeline.expire(key_burst, 1)
                pipeline.zadd(key_normal, {query: int(time.time())})
                pipeline.expire(key_normal, 3600)
                pipeline.execute()
            if prefix is not None:
                query = f'{prefix} {query}'
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
                logger.info(f"Redis cache hit for {query}")
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
            logger.error(f"Empty response for {query}")

        if self.broken.get(server) is not None:
            response += self.broken.get(server)
        return response

    def store_whois(self, domain, response):
        response_hash = hashlib.sha256(response.lower().encode()).hexdigest()
        if self.redis_whowas.exists(response_hash):
            return
        # only store if the value hasn't been set today.
        if self.redis_whowas.hsetnx(domain, datetime.date.today().isoformat(), response_hash):
            logger.info(f"Store {domain} in whowas.")
            self.redis_whowas.set(response_hash, response)


def main():
    """
    Execute the daemon.
    """
    argparser = argparse.ArgumentParser(description='UWhois server')
    argparser.add_argument('-c', '--config', required=True, help='Path to the config file')
    args = argparser.parse_args()

    logging.config.fileConfig(args.config)

    logger.info(f"Reading config file at '{args.config}'")
    uwhois = UWhois(args.config)
    set_running('uwhoisd')
    net.start_service(uwhois.iface, uwhois.port, uwhois.whois)
    unset_running('uwhoisd')


if __name__ == '__main__':
    sys.exit(main())
