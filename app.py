#!/usr/bin/env python3
import base64
import json
import os
import sys
import traceback
import socket
import datetime
from itertools import takewhile
from time import sleep
from urllib.parse import urlparse

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
scan_delay = ""
try:
    vault_url = os.environ["VAULT_URL"]
    secret_shares = os.environ["VAULT_SECRET_SHARES"]
    secret_threshold = os.environ["VAULT_SECRET_THRESHOLD"]
    namespace = os.environ["NAMESPACE"]
    root_token = os.environ["VAULT_ROOT_TOKEN_SECRET"]
    vault_keys = os.environ["VAULT_KEYS_SECRET"]
    scan_delay = int(os.environ["VAULT_SCAN_DELAY"])
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
    if not scan_delay:
        scan_delay = 5
    else:
        print(f"Please check system variable {error}")
        exit(2)
try:
    config.load_incluster_config()
    client.configuration.assert_hostname = False
except kubernetes.config.config_exception.ConfigException:
    config.load_kube_config()
    client.configuration.assert_hostname = False

PAYLOAD = {
    "secret_shares": int(secret_shares),
    "secret_threshold": int(secret_threshold),
}
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
api_instance = client.CoreV1Api()
k8s_secret = client.V1Secret()

STATUS_INIT = 0
STATUS_UNSEAL = 1
STATUS_OK = 2
STATUS_ERROR = 3

def tracing_formatter(record):
    def function(f):
        return "/loguru/" not in f.filename

    frames = takewhile(function, traceback.extract_stack())
    stack = " > ".join("{}:{}:{}".format(f.filename, f.name, f.lineno) for f in frames)
    record["extra"]["stack"] = stack
    record["extra"]["timestamp"] = datetime.datetime.now(datetime.UTC).isoformat()
    return "{level} | {extra[timestamp]} {extra[stack]} - {message}\n{exception}"


def list_convert(lst):
    converted_dict = {i: lst[i] for i in range(0, len(lst))}
    return converted_dict


def init_vault(vault_instance_url):
    try:
        logger.info(f"Initializing Vault at {vault_instance_url}")
        init_vault = requests.put(
            f"{vault_instance_url}/v1/sys/init", data=json.dumps(PAYLOAD), verify=False  # nosec
        )
        response = init_vault.json()
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


def read_secret(name, vault_instance_url):
    k8s_secret = api_instance.read_namespaced_secret(
        name=name, namespace=namespace
    ).data
    for secret in k8s_secret.values():
        key = base64.b64decode(secret)
        vault_unseal(key.decode(), vault_instance_url)


def get_secret(name):
    secret = api_instance.read_namespaced_secret(name=name, namespace=namespace).data
    if secret:
        return True


def vault_unseal(key, vault_instance_url):
    payload = {"key": f"{key}"}
    try:
        requests.put(
            f"{vault_instance_url}/v1/sys/unseal",
            data=json.dumps(payload),
            verify=False,  # nosec
        )
    except requests.exceptions.ConnectionError:
        pass
    if key is None:
        pass
    else:
        logger.info(f"{vault_instance_url} has been provided an unseal key")


def get_seal_status(vault_instance_url, vault_initialized):
    try:
        get_seal = requests.get(
            f"{vault_instance_url}/v1/sys/seal-status", verify=False  # nosec
        )
        if not get_seal.json()["initialized"]:
            if vault_initialized:
                logger.info("Vault has already been initialized, establishing quorum instead")
                return STATUS_INIT # Return STATUS_INIT to establish quorum

            logger.info("Going to init and unseal Vault")
            try:
                delete_secret([root_token, vault_keys])
            except kubernetes.client.exceptions.ApiException:
                pass
            create_secrets(init_vault(vault_instance_url))

            logger.info(f"Unsealing {replica_url}")
            read_secret(vault_keys, vault_instance_url)

            return STATUS_INIT
        if get_seal.json()["sealed"]:
            logger.info(f"Unsealing {replica_url}")
            read_secret(vault_keys, vault_instance_url)

            return STATUS_UNSEAL
    except requests.exceptions.ConnectionError as err:
        logger.info(f"Got error {err}")
        return STATUS_ERROR
        
    return STATUS_OK

def delete_secret(secret_name):
    for secret in secret_name:
        secret_for_delete = api_instance.delete_namespaced_secret(
            name=secret, namespace=namespace
        )
        logger.info(f"Secret delete {secret_for_delete.details.name}")


def wait_for_quorum(replica_list, leader_url):
    payload = {"leader_api_addr": leader_url}
    leader_status = requests.get(
            f"{leader_url}/v1/sys/leader", verify=False #nosec
    )

    for vault_instance_url in replica_list:
        if vault_instance_url == leader_url:
            continue
        try:
            logger.info(f"Joining {vault_instance_url} to leader")

            requests.post(f"{vault_instance_url}/v1/sys/storage/raft/join",
                          data=json.dumps(payload),
                          verify=False, #nosec
            )

        except requests.exceptions.ConnectionError as err:
            logger.info(f"Got error {err}")
            return STATUS_ERROR

        logger.info(f"Unsealing {replica_url}")
        read_secret(vault_keys, vault_instance_url)

    quorum_established = False

    while not quorum_established:
        quorum_established = True
        for vault_instance_url in replica_list:
            if vault_instance_url == leader_url:
                continue

            status = requests.get(
                f"{vault_instance_url}/v1/sys/leader", verify=False #nosec
            )

            if not "leader_address" in status.json():
                quorum_established = False
                logger.info(f"{replica_url} is not ready: \"{status.json()}\"")
                continue
            if status.json()["leader_address"] == leader_url:
                logger.info(f"{vault_instance_url} has acknowledged "
                            f"{leader_url} as the leader")
            else:
                logger.info(f"{vault_instance_url} has not acknowledged "
                            f"{leader_url} as the leader")

                quorum_established = False
                break

        sleep(5)

    logger.info(f"Quorum has been established with {leader_url} as the leader")

if __name__ == "__main__":
    vault_initialized = False
    leader_url = ""

    logger.remove()
    logger.add(sys.stderr, format=tracing_formatter)
    logger.info("Start Vault auto unseal")
    
    url = urlparse(vault_url)
    vault_hostname = url.hostname
    vault_port = url.port
    
    logger.info(f"Vault Hostname: \"{vault_hostname}\" Vault Port: {vault_port}")

    while True:
        logger.info("Begin scan cycle")

        # When running multiple vault instances, the DNS query will return multiple IPs.
        # We want to iterate over each of those IPs to ensure each replica is unsealed.

        # getaddrinfo() returns a 5-touple of (family, type, proto, canonname, sockaddr)
        # Index 4 (sockaddr) is a touple of (ip_addr, port), so we're extracting
        # index 4 (the ip addr touple) and then indexing into that touple to get the
        # actual ip address (index 0) and the port (index 1).
        
        # Then use list comprehension to return a list of "http://{ip_addr}:{port}" to
        # iterate over
        try:
            vault_replicas = sorted([f"{url.scheme}://{x[4][0]}:{x[4][1]}" 
                                        for x in socket.getaddrinfo(vault_hostname, 
                                                vault_port, proto=socket.IPPROTO_TCP)])
        except socket.gaierror as err:
            logger.error(f"Failed to lookup DNS info: {err}")
            sleep(5)
            continue

        logger.info(f"Discovered Vault instance(s): {vault_replicas}")

        for replica_url in vault_replicas:
            status = get_seal_status(replica_url, vault_initialized)
            if status == STATUS_INIT:
                # Only set the Leader URL once
                if not vault_initialized:
                    vault_initialized = True
                    leader_url = replica_url

                logger.info("Vault was just initialized, waiting for quorum to be established")
                wait_for_quorum(vault_replicas, leader_url)

            if status == STATUS_UNSEAL:
                # If we've unsealed an instance, then by definition vault has been initialized
                vault_initialized = True

        sleep(scan_delay)
