#!/bin/bash
set -e -u -x
HOOKS_HOME="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"/..
cd $HOOKS_HOME
docker build -t gcr.io/qubeship/qube-git-listener -f Dockerfile-wsgi .