#!/usr/bin/env python3
import base64
import json
import os
import sys
import traceback
from itertools import takewhile
from time import sleep

import kubernetes
import requests
from kubernetes import client, config
from loguru import logger
from requests.packages.urllib3.exceptions import InsecureRequestWarning

secret_shares = ""  # nosec
secret_threshold = ""  # nosec
namespace = ""
root_token = ""  # nosec
vault_keys = ""  # nosec
try:
    vault_url = os.environ["VAULT_URL"]
    secret_shares = os.environ["VAULT_SECRET_SHARES"]
    secret_threshold = os.environ["VAULT_SECRET_THRESHOLD"]
    namespace = os.environ["NAMESPACE"]
    root_token = os.environ["VAULT_ROOT_TOKEN_SECRET"]
    vault_keys = os.environ["VAULT_KEYS_SECRET"]
    if not vault_url:
        raise KeyError
except KeyError as error:
    if not secret_shares:
        secret_shares = 5
    if not namespace:
        namespace = "default"
    if not root_token:
        root_token = "root-token"  # nosec
    if not vault_keys:
        vault_keys = "vault-keys"
    if not secret_threshold:
        secret_threshold = 5
    else:
        print(f"Please check system variable {error}")
        exit(2)
try:
    config.load_incluster_config()
    client.configuration.assert_hostname = False
except kubernetes.config.config_exception.ConfigException:
    config.load_kube_config()
    client.configuration.assert_hostname = False

PAYLOAD = {"secret_shares": secret_shares, "secret_threshold": secret_threshold}
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
api_instance = client.CoreV1Api()
k8s_secret = client.V1Secret()


def tracing_formatter(record):
    def function(f):
        return "/loguru/" not in f.filename

    frames = takewhile(function, traceback.extract_stack())
    stack = " > ".join("{}:{}:{}".format(f.filename, f.name, f.lineno) for f in frames)
    record["extra"]["stack"] = stack
    return "{level} | {extra[stack]} - {message}\n{exception}"


def list_convert(lst):
    converted_dict = {i: lst[i] for i in range(0, len(lst))}
    return converted_dict


def init_vault():
    try:
        inti_vault = requests.put(
            f"{vault_url}/v1/sys/init", data=json.dumps(PAYLOAD), verify=False  # nosec
        )
        response = inti_vault.json()
        return response
    except requests.exceptions.ConnectionError as err:
        logger.info(f"Got error {err}. Please check Vault api url/port")
        pass


def create_secrets(secret):
    k8s_secret.metadata = client.V1ObjectMeta(name=root_token)
    k8s_secret.type = "Opaque"
    k8s_secret.string_data = {"root_token": f"{secret['root_token']}"}
    try:
        api_instance.create_namespaced_secret(namespace=namespace, body=k8s_secret)
    except kubernetes.client.exceptions.ApiException:
        pass

    k8s_secret.metadata = client.V1ObjectMeta(name=vault_keys)
    k8s_secret.type = "Opaque"
    k8s_secret.string_data = list_convert(secret["keys"])
    try:
        api_instance.create_namespaced_secret(namespace=namespace, body=k8s_secret)
    except kubernetes.client.exceptions.ApiException:
        pass


def read_secret(name):
    k8s_secret = api_instance.read_namespaced_secret(
        name=name, namespace=namespace
    ).data
    for secret in k8s_secret.values():
        key = base64.b64decode(secret)
        vault_unseal(key.decode())


def get_secret(name):
    secret = api_instance.read_namespaced_secret(name=name, namespace=namespace).data
    if secret:
        return True


def vault_unseal(key):
    payload = {"key": f"{key}"}
    try:
        requests.put(
            f"{vault_url}/v1/sys/unseal",
            data=json.dumps(payload),
            verify=False,  # nosec
        )
    except requests.exceptions.ConnectionError:
        pass
    if key is None:
        pass
    else:
        logger.info(f"Vault has been unsealed via key {key}")


def get_seal_status():
    try:
        get_seal = requests.get(
            f"{vault_url}/v1/sys/seal-status", verify=False  # nosec
        )
        if not get_seal.json()["initialized"]:
            logger.info("Going to init and unseal Vault")
            delete_secret([root_token, vault_keys])
            create_secrets(init_vault())
        if get_seal.json()["sealed"]:
            vault_unseal(read_secret("vault-keys"))
    except requests.exceptions.ConnectionError as err:
        logger.info(f"Got error {err}")
        pass


def delete_secret(secret_name):
    for secret in secret_name:
        secret_for_delete = api_instance.delete_namespaced_secret(
            name=secret, namespace=namespace
        )
        logger.info(f"Secret delete {secret_for_delete.details.name}")


if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stderr, format=tracing_formatter)
    logger.info("Start Vault auto unseal")
    while True:
        get_seal_status()
        sleep(5)
