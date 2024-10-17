#!/bin/bash

set -e
set -x

if [ -f  ../../valkey/src/valkey-server ]; then
    ../../valkey/src/valkey-server ./whowas.conf
elif [ -f ../../redis/src/redis-server ]; then
    ../../redis/src/redis-server ./whowas.conf
else
    echo "Warning: using system redis-server. Valkey-server or redis-server from source is recommended." >&2
    /usr/bin/redis-server ./whowas.conf
fi
