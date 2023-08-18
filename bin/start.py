#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen
from uwhoisd.default import get_homedir


def main() -> None:
    # Just fail if the env isn't set.
    get_homedir()
    p = Popen(['run_backend', '--start'])
    p.wait()
    Popen(['uwhoisd_manager'])


if __name__ == '__main__':
    main()
