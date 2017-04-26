#!/usr/bin/env bash
set -o allexport

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

if [ -e .env ]; then
	source .env
fi

TARGET_DEFAULT=$(docker-machine ip):${DEFAULT_LISTENER_PORT}
#TARGET_DEFAULT=$(docker ps --format '{{.Names}}' | grep
# githubwebhooks_git_listener)
TARGET=${NGROK_TARGET:-$TARGET_DEFAULT}

docker-compose -f docker-compose.yaml up -d --remove-orphans

docker run --name ngrok --rm -it --env-file .env -p 4040:4040 wernight/ngrok \
ngrok http --authtoken ${NGROK_AUTH} -hostname ${NGROK_HOSTNAME} ${TARGET}