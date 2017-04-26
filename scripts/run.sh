#!/usr/bin/env bash
set -o allexport

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

if [ -e .env ]; then
	source .env
fi
if [ -z "$(which ngrok)" ]; then
     echo "Please install ngrok"
     exit -1;
fi
TARGET_DEFAULT=$(docker-machine ip):${DEFAULT_LISTENER_PORT}
TARGET=${NGROK_TARGET:-$TARGET_DEFAULT}

docker-compose -f docker-compose.yaml up -d --remove-orphans
ngrok authtoken  ${NGROK_AUTH}
ngrok http -hostname=${NGROK_HOSTNAME} ${TARGET}