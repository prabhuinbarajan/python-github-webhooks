FROM grahamdumpleton/mod-wsgi-docker:python-3.5

WORKDIR /app
COPY . /app
ENV PYTHONPATH /app
RUN apt-get update && apt-get install -y jq wget unzip
RUN wget https://releases.hashicorp.com/consul/0.7.1/consul_0.7.1_linux_amd64.zip
RUN unzip consul_0.7.1_linux_amd64.zip -d /usr/local/bin/

RUN mod_wsgi-docker-build

EXPOSE 80
CMD ["webhooks.py"]
ENTRYPOINT [ "./scripts/startup.sh" , "mod_wsgi-docker-start"]
