#!/bin/bash
#docker build -t githook -f Dockerfile-wsgi .
home_dir=`pwd`
docker run -d --name qube_githook \
      -v $home_dir/hooks:/app/hooks \
      -v $home_dir/config.json:/app/config.json \
      -p 5080:80 gcr.io/qubeship/gitlistener
