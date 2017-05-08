#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

if [ -e .env ]; then
  source .env
fi

docker build -t $GIT_LISTENER_IMAGE:$GIT_LISTENER_VERSION .
