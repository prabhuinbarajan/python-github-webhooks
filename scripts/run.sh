#!/bin/bash
docker rm -f qube_githook
home_dir=`pwd`
docker run -d --name qube_githook \
      -v $home_dir/hooks:/app/hooks \
      -v $home_dir/config.json.dev:/app/config.json \
      -p 5080:80 gcr.io/qubeship/gitlistener
