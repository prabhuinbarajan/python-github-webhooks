#!/bin/bash
set -o allexport

if [ -z "$(which jq)" ]; then
     echo "Please install jq"
     exit -1;
fi
if [ -z "$(which consul)" ]; then
     echo "Please install consul"
     exit -1;
fi

if [ "$CONF_SERVER_ADDR" != "" ]; then
  # 1. /dev/settings (common envs)
  consul kv get -http-addr=$CONF_SERVER_ADDR -token=$CONF_SERVER_TOKEN -datacenter=dc1 qubeship/envs/$ENV_TYPE/settings > settings_$ENV_TYPE.json
  cat settings_$ENV_TYPE.json

  # 2. /dev/<user> (user-specific envs)
  if [ "$ENV_ID" != "" ]; then
  	echo "merging $ENV_ID and $ENV_TYPE"
    consul kv get -http-addr=$CONF_SERVER_ADDR -token=$CONF_SERVER_TOKEN -datacenter=dc1 qubeship/envs/$ENV_TYPE/$ENV_ID/settings > settings_$ENV_ID.json
    cat settings_$ENV_ID.json
    # 2-1. merge 2 jsons
    jq -s add settings_$ENV_TYPE.json settings_$ENV_ID.json > settings.json
  else
  	echo "ENV_ID missing, using $ENV_TYPE settings cat settings_$ENV_TYPE.json > settings.json"
  	cat settings_$ENV_TYPE.json > settings.json
  fi

  # 4. export all envs but those: *ENV*
  # variables defined in environment override values in consul
  for key in `jq -r 'keys[]' settings.json`; do
    if [[ $key =~ ENV ]]; then
      continue; \
    fi;
    if [[ $key =~ TENANT ]]; then
      continue;
    fi;
    eval VALUE='$'$key;
    if [ -z "$(env | egrep -E "$key=$VALUE")"  ]; then
      VALUE=`jq .${key} settings.json | sed -e 's/\"//g'`;
      export $key=$VALUE;
      echo "exported " $key
    else
      echo "WARN  - using env override $key $VALUE";
    fi;
  done
  # 5. test
  env
fi

export MOD_WSGI_PROCESSES=${MOD_WSGI_PROCESSES:-2}
