#!/usr/bin/env bash
set -o allexport

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

if [ -e .env ]; then
	source .env
fi

docker-compose -f docker-compose.yaml up -d --remove-orphans