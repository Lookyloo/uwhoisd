#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from uwhoisd.helpers import is_running, get_socket_path
import time
import os
from redis import Redis
from uwhoisd.helpers import get_homedir
import signal


def main() -> None:
    r = Redis(unix_socket_path=get_socket_path('cache'), db=2)
    r.set('shutdown', 1)
    time.sleep(5)
    while True:
        running = is_running()
        if not running:
            break
        print(running)
        time.sleep(5)


if __name__ == '__main__':
    main()
