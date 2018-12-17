#!/bin/bash

# set -e
set -x

../../redis/src/redis-cli -s ./whowas.sock shutdown
