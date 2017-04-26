# -*- coding: utf-8 -*-
#
# Copyright (C) 2014, 2015, 2016 Carlos Jenkins <carlos@jenkins.co.cr>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import sys
import logging

if sys.version_info < (3, 0):
    from urlparse import urlparse,parse_qs
else:
    from urllib.parse import urlparse, parse_qs  # noqa: F401

from sys import stderr, hexversion
logging.basicConfig(stream=stderr)

import hmac
import hvac

from hashlib import sha1
from json import loads, dumps
from subprocess import Popen, PIPE
from tempfile import mkstemp
import os
from os import access, X_OK, remove, fdopen
from os.path import isfile, abspath, normpath, dirname, join, basename

import requests
from ipaddress import ip_address, ip_network
from flask import Flask, request, abort


application = Flask(__name__)
DEFAULT_HOST = os.environ.get('DEFAULT_LISTENER_HOST', 'localhost')
DEFAULT_PORT = int(os.environ.get('DEFAULT_LISTENER_PORT', '5001'))
DEBUG = os.environ.get('DEBUG', 'False') \
    in ("yes", "y", "true", "True", "t", "1")


def get_qube_platform_secret_from_vault(vault_addr, vault_token, environment_type, environment_id ):
    secret = None
    if vault_token and environment_type:
        client = hvac.Client(url=vault_addr, token=vault_token)
        env_type_vault_path="secret/resources/qubeship/"+environment_type
        env_type_secret = ""
        env_type_vault_result = {}
        try:
            env_type_vault_result = client.read(env_type_vault_path +
                                                "/st2_api_key")
            env_type_secret = env_type_vault_result["data"]["value"]
        except Exception as ex:
            logging.info("error reading vault key from path:  {} {} ",
                         env_type_vault_path + "/st2_api_key",  ex)
            pass
        env_id_secret = ""
        try:
            if environment_id:
                env_id_vault_path = env_type_vault_path + "/"+environment_id
                env_id_vault_result = client.read(env_id_vault_path +
                                                  "/st2_api_key")
                env_id_secret = env_id_vault_result["data"]["value"]
        except Exception as ex:
            logging.info("error reading vault key from path:  {} {} ",
                         env_id_vault_path + "/st2_api_key",  ex)
            pass
        secret = env_type_secret if env_type_secret else env_id_secret

    return secret


def init_from_env():
    environment_id = os.getenv('ENV_ID', '')
    environment_type = os.getenv('ENV_TYPE', '')
    vault_addr = os.getenv('VAULT_ADDR', '')
    vault_token = os.getenv('VAULT_TOKEN', '')
    qube_secret_key_from_vault = get_qube_platform_secret_from_vault(
        vault_addr, vault_token, environment_type, environment_id)
    secret_key_env = os.getenv('QUBE_SECRET_KEY', qube_secret_key_from_vault)
    return secret_key_env

qube_secret_key_env = init_from_env()


@application.route('/', methods=['GET', 'POST'],strict_slashes=None)
def index():
    """
    Main WSGI application entry.
    """

    path = normpath(abspath(dirname(__file__)))
    hooks = join(path, 'hooks')

    # Only POST is implemented
    if request.method != 'POST':
        abort(501)

    # Load config
    with open(join(path, 'config.json'), 'r') as cfg:
        config = loads(cfg.read())

    # Allow Github IPs only
    if config.get('github_ips_only', True):
        src_ip = ip_address(
            u'{}'.format(request.remote_addr)  # Fix stupid ipaddress issue
        )
        whitelist = requests.get('https://api.github.com/meta').json()['hooks']

        for valid_ip in whitelist:
            if src_ip in ip_network(valid_ip):
                break
        else:
            abort(403)

    # Enforce secret
    secret = config.get('enforce_secret', '')
    qube_url_def = config.get('qube_url','')
    qube_url = os.getenv('QUBE_URL', qube_url_def)
    query_parts = parse_qs(urlparse(request.url).query)
    qube_project_id = query_parts['qube_proj_id'][0]
    qube_tenant_id = query_parts['qube_tenant_id'][0]
    qube_org_id = query_parts['qube_org_id'][0]
    qube_tenant_dns_prefix = query_parts['qube_dns_prefix'][0] if \
        'qube_dns_prefix' in query_parts else ""
    logging.info("qube_secret_key_env:  {}", qube_secret_key_env)
    print("qube_secret_key_env: ", qube_secret_key_env)

    if secret:
        # Only SHA1 is supported
        header_signature = request.headers.get('X-Hub-Signature')
        if header_signature is None:
            abort(403)

        sha_name, signature = header_signature.split('=')
        if sha_name != 'sha1':
            abort(501)

        # HMAC requires the key to be bytes, but data is string
        mac = hmac.new(str(secret), msg=request.data, digestmod=sha1)

        # Python prior to 2.7.7 does not have hmac.compare_digest
        if hexversion >= 0x020707F0:
            if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                abort(403)
        else:
            # What compare_digest provides is protection against timing
            # attacks; we can live without this protection for a web-based
            # application
            if not str(mac.hexdigest()) == str(signature):
                abort(403)

    # Implement ping
    event = request.headers.get('X-GitHub-Event', 'ping')
    if event == 'ping':
        return dumps({'msg': 'pong'})

    # Gather data
    try:
        payload = loads(to_string(request.data))
    except Exception as ex:
        abort(400)

    # Determining the branch is tricky, as it only appears for certain event
    # types an at different levels
    branch = None
    tag = None
    try:
        # Case 1: a ref_type indicates the type of ref.
        # This true for create and delete events.
        if 'ref_type' in payload:
            if payload['ref_type'] == 'branch':
                branch = payload['ref']

        # Case 2: a pull_request object is involved. This is pull_request and
        # pull_request_review_comment events.
        elif 'pull_request' in payload:
            # This is the TARGET branch for the pull-request, not the source
            # branch
            branch = payload['pull_request']['base']['ref']

        elif event in ['push']:
            # Push events provide a full Git ref in 'ref' and not a 'ref_type'.
            branch = payload['ref'].split('/')[2]

        elif event in ['release']:
            tag = payload['release']['tag_name']

    except KeyError:
        # If the payload structure isn't what we expect, we'll live without
        # the branch name
        pass

    # All current events have a repository, but some legacy events do not,
    # so let's be safe
    name = payload['repository']['name'] if 'repository' in payload else None

    meta = {
        'name': name,
        'branch': branch,
        'event': event,
        'tag': tag
    }
    logging.info('Metadata:\n{}'.format(dumps(meta)))
    dyn_pl=request.args.get('key', '')
    # Possible hooks
    scripts = []
    if branch and name:
        scripts.append(join(hooks, '{event}-{name}-{branch}'.format(**meta)))
    if name:
        scripts.append(join(hooks, '{event}-{name}'.format(**meta)))
    if tag:
        scripts.append(join(hooks, '{event}-{name}-{tag}'.format(**meta)))
    scripts.append(join(hooks, '{event}'.format(**meta)))
    scripts.append(join(hooks, 'all'))

    # Check permissions
    scripts = [s for s in scripts if isfile(s) and access(s, X_OK)]
    if not scripts:
        return ''

    # Save payload to temporal file
    osfd, tmpfile = mkstemp()
    with fdopen(osfd, 'w') as pf:
        pf.write(dumps(payload))

    # Run scripts
    ran = {}
    for s in scripts:

        proc = Popen([s, tmpfile, event, request.host, qube_secret_key_env, qube_url, qube_project_id, qube_tenant_id, qube_tenant_dns_prefix, qube_org_id], stdout=PIPE, stderr=PIPE)

        stdout, stderr = proc.communicate()

        ran[basename(s)] = {
            'returncode': proc.returncode,
            'stdout': to_string(stdout),
            'stderr': to_string(stderr),
        }

        # Log errors if a hook failed
        if proc.returncode != 0:
            logging.error('{} : {} \n{}'.format(
                s, proc.returncode, stderr
            ))

    # Remove temporal file
    remove(tmpfile)

    info = config.get('return_scripts_info', False)
    if not info:
        return ''
    output = dumps(ran, sort_keys=True, indent=4)
    logging.info(output)
    return output

def to_string(input_str):
    """
    Python 3 default encoding: UTF-8
    Python 2 default encoding: ascii

    string b'STRING' is an instance of 'bytes' if py3
    hence we need to decode it.
    no need to decode if py2, because it's still the type of 'str'
    """
    return input_str.decode(sys.getdefaultencoding()) \
        if isinstance(input_str, bytes) else str(input_str)

if __name__ == '__main__':
    application.run(debug=DEBUG,
        host=DEFAULT_HOST,
        port=DEFAULT_PORT)
