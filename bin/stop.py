#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen
from uwhoisd.helpers import get_homedir, get_socket_path
from redis import Redis


def main() -> None:
    get_homedir()
    p = Popen(['shutdown'])
    p.wait()
    r = Redis(unix_socket_path=get_socket_path('cache'), db=2)
    r.delete('shutdown')
    Popen(['run_backend', '--stop'])


if __name__ == '__main__':
    main()
