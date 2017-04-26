#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

set -o allexport
export PYTHONPATH=$PWD
source .env

./scripts/startup.sh webhooks.py