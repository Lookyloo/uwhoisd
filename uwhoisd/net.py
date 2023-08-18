"""
Networking code.
"""

import contextlib
import logging
import socket
import time
from typing import Callable

import tornado
from tornado import gen
from tornado.ioloop import IOLoop
from tornado.tcpserver import TCPServer


from uwhoisd import utils

logger = logging.getLogger('uwhoisd')


class WhoisClient(object):
    """
    Whois client.
    """

    def __init__(self, server: str, port: int) -> None:
        """
        A WHOIS client for Tornado.

        :param server string: hostname of downstream server.
        :param port int: port on downstream server to connect to.
        """
        self.server = server
        self.port = port

    def __enter__(self) -> 'WhoisClient':
        """
        Initialize a `with` statement.
        """
        self.sock = socket.create_connection((self.server, self.port))
        self.sock.settimeout(10)
        return self

    def __exit__(self, type, value, traceback):
        """
        Terminate a `with` statement.
        """
        self.sock.close()

    def whois(self, query: str) -> str:
        """
        Perform a query against the server.
        """
        to_return = ''
        try:
            bytes_whois = b''
            self.sock.sendall('{0}\r\n'.format(query).encode())
            while data := self.sock.recv(2048):
                bytes_whois += data
            to_return = str(bytes_whois, 'utf-8', 'ignore')
        except OSError as e:
            # Catches all socket.* exceptions
            return '{0}: {1}\n'.format(self.server, e)
        except Exception:
            logger.exception("Unknown exception when querying '%s'", query)
        return to_return


@contextlib.contextmanager
def auto_timeout(self, timeout: int):
    """
    Create a timeout for the IOLoop.
    """
    try:
        handle = IOLoop.instance().add_timeout(time.time() + timeout,
                                               self.timed_out)
        yield handle
    except tornado.iostream.StreamClosedError:
        if not self._timed_out:
            logger.info("Stream Closed by client, no timeout.")
    except Exception:
        logger.exception("Unable to set timeout")
    finally:
        IOLoop.instance().remove_timeout(handle)


class ClientHandler(object):
    """
    Handle a uWhoisd client.
    """

    def __init__(self, stream, query_fct, client, timeout: int):
        """
        Handle a uWhoisd client.
        """
        self.stream = stream
        self.query_fct = query_fct
        self.client = client
        self.timeout = timeout
        self._timed_out = False

    @gen.coroutine
    def timed_out(self):
        """
        Close the stream if the client doesn't send a query fast enough.
        """
        self._timed_out = True
        logger.warning('Connection from %s timed-out.', self.client)
        try:
            yield self.stream.write("; Request timed out\r\n".encode())
        except Exception:
            logger.exception("Unknown exception by '%s'", self.client)
        finally:
            self.stream.close()

    @gen.coroutine
    def on_connect(self):
        """
        Handle a connexion.
        """
        try:
            with auto_timeout(self, self.timeout):
                self.data = yield self.stream.read_until_regex(br'\s')
            if not hasattr(self, 'data') or not self.data:
                return
            if self._timed_out:
                return
            whois_query = self.data.decode().strip().lower()
            if not utils.is_well_formed_fqdn(whois_query) and ':' not in whois_query and not whois_query.lower().startswith('as'):
                whois_entry = "; Bad request: '{0}'\r\n".format(whois_query)
            else:
                whois_entry = self.query_fct(whois_query)
            yield self.stream.write(whois_entry.encode())
        except tornado.iostream.StreamClosedError:
            logger.warning('Connection closed by %s.', self.client)
        except Exception:
            logger.exception("Unknown exception by '%s'", self.client)
        finally:
            self.stream.close()


class WhoisListener(TCPServer):
    """
    Listener for whois clients.
    """

    def __init__(self, whois: Callable[[str], str], timeout: int=15) -> None:
        """
        Listen to queries from whois clients.
        """
        super(WhoisListener, self).__init__()
        self.whois = whois
        self.timeout = timeout

    @gen.coroutine
    def handle_stream(self, stream, address):
        """
        Respond to a single request.
        """
        try:
            connection = ClientHandler(stream, self.whois, address,
                                       self.timeout)
            yield connection.on_connect()
        except Exception:
            # Something bad happened
            logger.exception("Unknown exception when handling '%s'", address)
        finally:
            stream.close()
