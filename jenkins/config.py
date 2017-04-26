from jenkinsapi.jenkins import Jenkins
import os
import hvac
import logging

from jenkinsapi.utils.crumb_requester import CrumbRequester


def get_qubebuilder_user_pwd(vault_addr, vault_token, environment_type,
                             environment_id):
    user = os.getenv('CI_USER', '')
    pwd = os.getenv('CI_TOKEN', '')

    if vault_token and environment_type:
        client = hvac.Client(url=vault_addr, token=vault_token)
        env_type_vault_path = "secret/resources/qubeship/" + environment_type
        env_type_user = user
        env_type_pwd = pwd
        try:
            env_type_vault_result = client.read(env_type_vault_path +
                                                "/qubebuilder")
            env_type_user = env_type_vault_result["data"]["user"]
            env_type_pwd = env_type_vault_result["data"]["access_token"]
            logging.info("located qubebuilder credentials in %".format(
                environment_type))
        except Exception as ex:
            logging.info("error reading vault key from path:  {} {} ",
                         env_type_vault_path + "/qubebuilder",  ex)
            pass
        env_id_user = ""
        env_id_pwd = ""
        env_id_vault_path = ""
        try:
            if environment_id:
                env_id_vault_path = env_type_vault_path + "/"+environment_id
                env_id_vault_result = client.read(env_id_vault_path +
                                                  "/qubebuilder")
                env_id_user = env_id_vault_result["data"]["user"]
                env_id_pwd = env_id_vault_result["data"]["access_token"]
                logging.info("located qubebuilder credentials in %".format(
                    environment_id))
        except Exception as ex:
            logging.info("error reading vault key from path:  {} {} ",
                         env_id_vault_path + "/qubebuilder",  ex)
            pass

        pwd = env_id_pwd if env_id_pwd else env_type_pwd
        user = env_id_user if env_id_user else env_type_user

    return user, pwd


def init_from_env():
    environment_id = os.getenv('ENV_ID', '')
    environment_type = os.getenv('ENV_TYPE', '')
    vault_addr = os.getenv('VAULT_ADDR', '')

    vault_token = os.getenv('VAULT_TOKEN', '')
    return get_qubebuilder_user_pwd(
        vault_addr, vault_token, environment_type, environment_id)

qube_user, qube_pwd = init_from_env()


class QubeConfig:
  """
    Qube Config to pass around the jenkins server context
  """
  def __init__(self, *args, **kwargs):

    ci_addr = os.getenv('CI_ADDR', 'https://builder.qubeship.io')
    crumb_requester = CrumbRequester(baseurl=ci_addr, username=qube_user,
                                     password=qube_pwd)
    self.server = Jenkins(ci_addr, username=qube_user, password=qube_pwd,
                          requester=crumb_requester)
