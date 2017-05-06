from jenkinsapi.jenkins import Jenkins
import os
import hvac
import logging

from jenkinsapi.utils.crumb_requester import CrumbRequester


def get_qubebuilder_user_pwd(vault_addr, vault_token, environment_type,
                             environment_id):
    user = os.getenv('CI_USER', '')
    pwd = os.getenv('CI_TOKEN', '')
    ci_addr = os.getenv('CI_ADDR', 'https://builder.qubeship.io')

    if vault_token and environment_type:
        client = hvac.Client(url=vault_addr, token=vault_token)
        env_type_vault_path = "secret/resources/qubeship/" + environment_type
        env_type_user = user
        env_type_pwd = pwd
        env_type_ci_addr = ci_addr
        try:
            env_type_vault_result = client.read(env_type_vault_path +
                                                "/qubebuilder")
            if env_type_vault_result:
                env_type_user = env_type_vault_result["data"]["user"]
                env_type_pwd = env_type_vault_result["data"]["access_token"]
                logging.info("located qubebuilder credentials in %".format(
                    environment_type))
            else:
                logging.info("skip to read keys from path: {}/{}".format(
                    env_type_vault_path, "qubebuilder"))
        except Exception as ex:
            logging.info("error reading vault key from path: {}/{} {}".format(
                env_type_vault_path, "qubebuilder",  ex))
            pass
        env_id_user = ""
        env_id_pwd = ""
        env_id_ci_addr = ""
        env_id_vault_path = ""
        try:
            if environment_id:
                env_id_vault_path = env_type_vault_path + "/"+environment_id
                env_id_vault_result = client.read(env_id_vault_path +
                                                  "/qubebuilder")
                if env_id_vault_result:
                    env_id_user = env_id_vault_result["data"]["user"]
                    env_id_pwd = env_id_vault_result["data"]["access_token"]
                    logging.info("located qubebuilder credentials in %".format(
                        environment_id))
                else:
                    logging.info("skip to read keys from path: {}/{}".format(
                        env_id_vault_path, "qubebuilder"))
        except Exception as ex:
            logging.info("error reading vault key from path: {}/{} {}".format(
                env_id_vault_path, "qubebuilder", ex))
            pass

        pwd = env_id_pwd if env_id_pwd else env_type_pwd
        user = env_id_user if env_id_user else env_type_user
        ci_addr = env_id_ci_addr if env_id_ci_addr else env_type_ci_addr

    return user, pwd, ci_addr


def init_from_env():
    environment_id = os.getenv('ENV_ID', '')
    environment_type = os.getenv('ENV_TYPE', '')
    vault_addr = os.getenv('VAULT_ADDR', '')

    vault_token = os.getenv('VAULT_TOKEN', '')
    return get_qubebuilder_user_pwd(
        vault_addr, vault_token, environment_type, environment_id)

qube_user, qube_pwd, qube_ci_addr = init_from_env()


class QubeConfig:
    """
    Qube Config to pass around the jenkins server context
    """
    def __init__(self, *args, **kwargs):
        crumb_requester = CrumbRequester(baseurl=qube_ci_addr, username=qube_user,
                                         password=qube_pwd)
        self.server = Jenkins(qube_ci_addr, username=qube_user, password=qube_pwd,
                              requester=crumb_requester)
