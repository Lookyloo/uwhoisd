#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket


class Uwhois(object):

    def __init__(self, server='127.0.0.1', port=4243):
        self.server = server
        self.port = port

    def query(self, q):
        bytes_whois = b''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.server, self.port))
            sock.sendall('{}\n'.format(q).encode())
            while True:
                data = sock.recv(2048)
                if data:
                    bytes_whois += data
                    continue
                break
        return bytes_whois.decode()
