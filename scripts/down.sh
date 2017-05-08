#!/usr/bin/env bash
set -o allexport

docker-compose down --remove-orphans
ps -ef | grep ngrok | grep -v grep | awk '{print $2}' | xargs kill -9