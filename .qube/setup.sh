#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd ${DIR}/..

NS=platform

kubectl create secret generic qube-git-listener-config --from-file=keys/listener.api.key --namespace=${NS}