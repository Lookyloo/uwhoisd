#!/usr/bin/env python3

import asyncio
import logging
import signal

import logging.config

from typing import Optional

import tornado
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.netutil import bind_sockets

from uwhoisd.default import AbstractManager, get_homedir, get_config
from uwhoisd.net import WhoisListener
from uwhoisd import UWhois

logging.config.dictConfig(get_config('logging'))


def handle_signal(sig, frame) -> None:
    """
    Stop the main loop on signal.
    """
    IOLoop.instance().add_callback(IOLoop.instance().stop)


class ShutdownCallback(PeriodicCallback):

    def stop(self) -> None:
        self.io_loop.stop()


class UWhoisdManager(AbstractManager):

    def __init__(self, loglevel: Optional[int]=None):
        super().__init__(loglevel)
        self.script_name = 'uwhoisd'

        self.default_config = get_homedir() / 'extra' / 'uwhoisd.ini'
        logging.config.fileConfig(self.default_config)
        self.logger.info(f"Reading config file at '{self.default_config}'")
        self.uwhois = UWhois(self.default_config)
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

    async def _to_run_forever_async(self):
        self.logger.info("Listen on %s:%d", self.uwhois.iface, self.uwhois.port)
        sockets = bind_sockets(self.uwhois.port, self.uwhois.iface)
        tornado.process.fork_processes(0)

        async def post_fork_main():
            server = WhoisListener(self.uwhois.whois, 15)
            server.add_sockets(sockets)

            def callback() -> None:
                if self.shutdown_requested():
                    pc.stop()

            pc = ShutdownCallback(callback, 1000)
            pc.start()

            await asyncio.Event().wait()

        asyncio.run(post_fork_main())


def main():
    w = UWhoisdManager()
    loop = asyncio.new_event_loop()

    try:
        loop.run_until_complete(w.run_async(sleep_in_sec=1))
    finally:
        loop.close()
