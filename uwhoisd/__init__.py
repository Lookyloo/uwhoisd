"""
A 'universal' WHOIS proxy server.
"""

import logging
import logging.config
import re
import socket
import shlex
from subprocess import Popen, PIPE
import time
import datetime
import configparser
import hashlib
import argparse
from typing import Dict, Optional, Tuple

from publicsuffix2 import PublicSuffixList, fetch  # type: ignore

from . import net, utils
from .helpers import set_running, unset_running, get_socket_path


logger = logging.getLogger('uwhoisd')
try:
    import redis
    redis_lib = True
except ImportError:
    logger.warning('Redis module unavailable, redis cache, rate limiting and whowas unavailable')
    redis_lib = False


# Initialize Public Suffix List
try:
    psl_file = fetch()
    psl = PublicSuffixList(psl_file=psl_file)
except Exception as e:
    logger.warning(f'Unable to fetch the PublicSuffixList: {e}')
    psl = PublicSuffixList()


PORT = socket.getservbyname('whois', 'tcp')


class UWhois(object):
    """
    Universal WHOIS proxy.
    """

    broken: Dict[str, str]
    tld_no_whois: Dict[str, str]
    overrides: Dict[str, str]
    prefixes: Dict[str, str]
    ratelimit: Dict[str, str]

    def __init__(self, config_path: str):
        parser = configparser.ConfigParser()
        parser.read(config_path)
        self.read_config(parser)
        self.iface = parser.get('uwhoisd', 'iface')
        self.port = parser.getint('uwhoisd', 'port')

    def _get_dict(self, parser: configparser.ConfigParser, section: str) -> None:
        """
        Pull a dictionary out of the config safely.
        """
        if parser.has_section(section):
            values = dict((key, utils.decode_value(value)) for key, value in parser.items(section))
        else:
            values = {}
        setattr(self, section, values)

    def read_config(self, parser: configparser.ConfigParser) -> None:
        """
        Read the configuration for this object from a config file.
        """
        self.registry_whois = parser.getboolean('uwhoisd', 'registry_whois')
        self.page_feed = parser.getboolean('uwhoisd', 'page_feed')

        for section in ('overrides', 'prefixes', 'broken', 'tld_no_whois'):
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

    def get_overwritten_whois_server(self, zone: str) -> Tuple[str, int]:
        """
        Get the WHOIS server for the given zone.
        """
        server = self.overrides[zone]
        port: int
        if ':' in server:
            server, p = server.split(':', 1)
            port = int(p)
        else:
            port = int(PORT)
        return server, port

    def get_registrar_whois_server(self, pattern, response: str) -> Optional[str]:  # type: ignore
        """
        Extract the registrar's WHOIS server from the registry response.
        """
        matches = pattern.search(response)
        return None if matches is None else matches.group('server')

    def get_prefix(self, server: str) -> Optional[str]:
        """
        Gets the prefix required when querying the servers.
        """
        return self.prefixes.get(server)

    def get_recursion_pattern(self, server: str):  # type: ignore
        """
        Get the recursion pattern after querying a server.
        """
        return self.recursion_patterns.get(server)

    def _run_query(self, server: str, port: int, query: str, prefix: Optional[str]='', is_recursive: bool=False) -> str:
        """
        Run the query against a server.
        """
        ratelimit_details = self.ratelimit.get(server)
        if ratelimit_details:
            per_sec, per_hour = ratelimit_details.split()
            key_burst = f'{server}_burst'
            key_normal = f'{server}_normal'
        if self.redis_ratelimit is not None and ratelimit_details is not None:
            while self.redis_ratelimit.zcard(key_burst) > int(per_sec):  # type: ignore
                # Max queries per sec reached
                logger.info(f"Rate limiting on {server} (burst)")
                time.sleep(.3)
                # Remove all the keys that are at least 1 sec old
                self.redis_ratelimit.zremrangebyscore(key_burst, '-inf', time.time() - 1)
            while self.redis_ratelimit.zcard(key_normal) > int(per_hour):  # type: ignore
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

    def _thin_query(self, pattern, response: str, port: int, query: str) -> str:  # type: ignore
        """
        Query a more detailled Whois server if possible.
        """
        # FIXME: if a port is provided in the response, it is ignored.
        server = self.get_registrar_whois_server(pattern, response)
        if server is not None:
            prefix = self.get_prefix(server)
            if not self.registry_whois:
                response = ""
            elif self.page_feed:
                # A form feed character so it's possible to find the split.
                response += "\f"
            try:
                response += self._run_query(server, port, query, prefix, True)
            except TimeoutError:
                logger.exception(f'The whois query failed: {server}:{port} - {query} - {prefix}')
            except socket.gaierror:
                logger.exception(f'The whois query failed: {server}:{port} - {query} - {prefix}')
        return response

    def _strip_hostname(self, query: str) -> Tuple[str, str]:
        """A whois query on a hostname will fail. This method uses the Mozilla TLD list
        to only keep the domain part and remove everything else."""
        tld = psl.get_tld(query, strict=True)
        hostname = re.sub(rf"\.{tld}$", "", query)
        if '.' in hostname:
            domain = hostname.split('.')[-1]
            return f'{domain}.{tld}', tld
        return query, tld

    def whois(self, query: str) -> str:
        """
        Query the appropriate WHOIS server.
        """
        if query.split('.')[-1].isdigit():
            # IPv4, doesn't matter, always fallback to system whois
            zone = 'ipv4'
        elif ':' in query:
            # IPv6, doesn't matter, always fallback to system whois
            zone = 'ipv6'
        elif 'as' in query.lower():
            zone = 'asn'
        else:
            # Domain, strip hostname part if needed
            query, zone = self._strip_hostname(query)

        response: str
        if self.redis_cache:
            response = self.redis_cache.get(query)  # type: ignore
            if response:
                logger.info(f"Redis cache hit for {query}")
                return response

        if zone in self.overrides:
            server, port = self.get_overwritten_whois_server(zone)
            # Query the registry's WHOIS server.
            prefix = self.get_prefix(server)
            try:
                response = self._run_query(server, port, query, prefix)
            except TimeoutError:
                logger.exception(f'The whois query failed: {server}:{port} - {query} - {prefix}')
            except socket.gaierror:
                logger.exception(f'The whois query failed: {server}:{port} - {query} - {prefix}')

            # Thin registry? Query the registrar's WHOIS server.
            recursion_pattern = self.get_recursion_pattern(server)
            if recursion_pattern is not None:
                response = self._thin_query(recursion_pattern, response, port, query)

        else:
            # Just use the system whois command
            command = shlex.split(f'whois --verbose {query}')
            proc = Popen(command, stdout=PIPE, stderr=PIPE)
            out, err = proc.communicate()
            try:
                s, _, response = out.decode().strip().split('\n', 2)
                server = re.findall('Using server (.*).', s)[0]
                logger.info(f'Queried {server} about {query}')
            except Exception as e:
                logger.warning(f'Error with query "{query}": {e}')
                server = ''
                response = out.decode()
                logger.warning(f'Response: {response}')

        if response:
            if self.redis_cache:
                self.redis_cache.setex(query, self.cache_expire, response)
            if self.redis_whowas:
                self.store_whois(query, response)
        else:
            logger.error(f"Empty response for {query}")

        if server and self.broken.get(server) is not None:
            response += '\n' + self.broken[server]
        elif self.tld_no_whois.get(zone) is not None:
            response += '\n' + self.tld_no_whois[zone]
        return response

    def store_whois(self, domain: str, response: str) -> None:
        response_hash = hashlib.sha256(response.lower().encode()).hexdigest()
        if self.redis_whowas.exists(response_hash):
            return None
        # only store if the value hasn't been set today.
        if self.redis_whowas.hsetnx(domain, datetime.date.today().isoformat(), response_hash):
            logger.info(f"Store {domain} in whowas.")
            self.redis_whowas.set(response_hash, response)


def main() -> None:
    """
    Execute the daemon.
    """
    argparser = argparse.ArgumentParser(description='UWhois server')
    argparser.add_argument('-c', '--config', type=str, required=True, help='Path to the config file')
    args = argparser.parse_args()

    logging.config.fileConfig(args.config)

    logger.info(f"Reading config file at '{args.config}'")
    uwhois = UWhois(args.config)
    set_running('uwhoisd')
    net.start_service(uwhois.iface, uwhois.port, uwhois.whois)
    unset_running('uwhoisd')


if __name__ == '__main__':
    main()
