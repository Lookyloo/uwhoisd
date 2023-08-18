#!/usr/bin/env python3

import argparse
import os
import time
from pathlib import Path
from subprocess import Popen
from typing import Optional, Dict

from redis import Redis
from redis.exceptions import ConnectionError

from uwhoisd.default import get_homedir, get_socket_path


def check_running(name: str) -> bool:
    socket_path = get_socket_path(name)
    if not os.path.exists(socket_path):
        print(socket_path, 'missing')
        return False
    try:
        r = Redis(unix_socket_path=socket_path)
        return True if r.ping() else False
    except ConnectionError:
        return False


def launch_cache(storage_directory: Optional[Path]=None):
    if not storage_directory:
        storage_directory = get_homedir()
    if not check_running('cache'):
        Popen(["./run_redis.sh"], cwd=(storage_directory / 'cache'))


def launch_whowas(storage_directory: Optional[Path]=None):
    if not storage_directory:
        storage_directory = get_homedir()
    if not check_running('whowas'):
        Popen(["./run_redis.sh"], cwd=(storage_directory / 'whowas'))


def shutdown_cache(storage_directory: Optional[Path]=None):
    if not storage_directory:
        storage_directory = get_homedir()
    r = Redis(unix_socket_path=get_socket_path('cache'))
    r.shutdown(save=True)
    print('Redis cache database shutdown.')


def shutdown_whowas(storage_directory: Optional[Path]=None):
    if not storage_directory:
        storage_directory = get_homedir()
    r = Redis(unix_socket_path=get_socket_path('whowas'))
    r.shutdown(save=True)
    print('Redis whowas database shutdown.')


def launch_all():
    launch_cache()
    launch_whowas()


def check_all(stop: bool=False):
    backends: Dict[str, bool] = {'cache': False, 'whowas': False}
    while True:
        for db_name in backends.keys():
            try:
                backends[db_name] = check_running(db_name)
            except Exception:
                backends[db_name] = False
        if stop:
            if not any(running for running in backends.values()):
                break
        else:
            if all(running for running in backends.values()):
                break
        for db_name, running in backends.items():
            if not stop and not running:
                print(f"Waiting on {db_name} to start")
            if stop and running:
                print(f"Waiting on {db_name} to stop")
        time.sleep(1)


def stop_all():
    shutdown_cache()
    shutdown_whowas()


def main():
    parser = argparse.ArgumentParser(description='Manage backend DBs.')
    parser.add_argument("--start", action='store_true', default=False, help="Start all")
    parser.add_argument("--stop", action='store_true', default=False, help="Stop all")
    parser.add_argument("--status", action='store_true', default=True, help="Show status")
    args = parser.parse_args()

    if args.start:
        launch_all()
    if args.stop:
        stop_all()
    if not args.stop and args.status:
        check_all()


if __name__ == '__main__':
    main()
