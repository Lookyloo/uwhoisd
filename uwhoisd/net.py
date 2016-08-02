"""
Networking code.
"""

import logging
import signal
import socket

from tornado import gen
from tornado.ioloop import IOLoop
from tornado.tcpserver import TCPServer

from uwhoisd import utils

CRLF = b'\r\n'

logger = logging.getLogger('uwhoisd')


def handle_signal(sig, frame):
    IOLoop.instance().add_callback(IOLoop.instance().stop)


class WhoisClient(object):

    def __init__(self, server, port):
        self.server = server
        self.port = port

    def whois(self, query):
        to_return = b''
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.server, self.port))
                sock.sendall('{}\n'.format(query).encode())
                while True:
                    data = sock.recv(2048)
                    if data:
                        to_return += data
                        continue
                    break
        except OSError as e:
            # Catches all socket.* exceptions
            return '{}: {}\n'.format(self.server, e)
        except ConnectionError as e:
            # Catches all Connection*Error exceptions
            return '{}: {}\n'.format(self.server, e)
        except Exception as e:
            logger.exception(e)
        return to_return.decode()


class WhoisListener(TCPServer):

    def __init__(self, whois):
        super(WhoisListener, self).__init__()
        self.whois = whois

    @gen.coroutine
    def handle_stream(self, stream, address):
        self.stream = stream
        try:
            whois_query = yield self.stream.read_until(CRLF)
            whois_query = whois_query.decode().strip().lower()
            if not utils.is_well_formed_fqdn(whois_query) and ':' not in whois_query:
                whois_entry = "; Bad request: '{}'\r\n".format(whois_query)
            else:
                whois_entry = self.whois(whois_query)
            yield self.stream.write(whois_entry.encode())
        except Exception as e:
            logger.exception(e)
        self.stream.close()


def start_service(iface, port, whois):
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    server = WhoisListener(whois)
    server.listen(port, iface)
    IOLoop.instance().start()
    IOLoop.instance().close()
