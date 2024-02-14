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
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_kubernetes_client():
    try:
        config.load_incluster_config()
        client.configuration.assert_hostname = False
    except kubernetes.config.config_exception.ConfigException:
        config.load_kube_config()
        client.configuration.assert_hostname = False
    return client


def tracing_formatter(record):
    def function(f):
        return "/loguru/" not in f.filename

    frames = takewhile(function, traceback.extract_stack())
    stack = " > ".join("{}:{}:{}".format(f.filename, f.name, f.lineno) for f in frames)
    record["extra"]["stack"] = stack
    record["extra"]["timestamp"] = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat()
    return "{level} | {extra[timestamp]} {extra[stack]} - {message}\n{exception}"


def list_convert(lst):
    converted_dict = {i: lst[i] for i in range(0, len(lst))}
    return converted_dict


def init_vault(vault_instance_url):
    try:
        logger.info(f"Initializing Vault at {vault_instance_url}")
        init_vault_request = requests.put(
            f"{vault_instance_url}/v1/sys/init",
            data=json.dumps(auto_unseal_payload),
            verify=False,  # nosec
        )
        response = init_vault_request.json()
        return response
    except requests.exceptions.ConnectionError as init_vault_error:
        logger.info(
            "Got ConnectionError for  {}. Please check Vault api url/port",
            init_vault_error,
        )


def create_secrets(secret):
    k8s_secret.metadata = client.V1ObjectMeta(name=root_token)
    k8s_secret.type = "Opaque"
    k8s_secret.string_data = {"root_token": secret["root_token"]}
    try:
        api_instance.create_namespaced_secret(namespace=namespace, body=k8s_secret)
    except kubernetes.client.exceptions.ApiException as create_secret_error:
        logger.error("Error during creation on Vault secret {}", create_secret_error)

    k8s_secret.metadata = client.V1ObjectMeta(name=vault_keys)
    k8s_secret.type = "Opaque"
    k8s_secret.string_data = list_convert(secret["keys"])
    try:
        api_instance.create_namespaced_secret(namespace=namespace, body=k8s_secret)
    except kubernetes.client.exceptions.ApiException as create_secret_error:
        logger.error("Error during creation on Vault secret {}", create_secret_error)


def read_secret(name, vault_instance_url):
    secret_client = api_instance.read_namespaced_secret(
        name=name, namespace=namespace
    ).data
    for secret in secret_client.values():
        key = base64.b64decode(secret)
        vault_unseal(key.decode(), vault_instance_url)


def get_secret(name):
    secret = api_instance.read_namespaced_secret(name=name, namespace=namespace).data
    if secret:
        return True


def vault_unseal(key, vault_instance_url):
    payload = {"key": key}
    try:
        requests.put(
            f"{vault_instance_url}/v1/sys/unseal",
            data=json.dumps(payload),
            verify=False,  # nosec
        )
    except requests.exceptions.ConnectionError as unseal_error:
        logger.error("During unseal got error", unseal_error)
    if key is None:
        logger.info("Unseal key not found")
    else:
        logger.info("{} has been provided an unseal key", vault_instance_url)


def get_seal_status(vault_instance_url, vault_status):
    try:
        get_seal = requests.get(
            f"{vault_instance_url}/v1/sys/seal-status", verify=False  # nosec
        )
        if not get_seal.json()["initialized"]:
            if vault_status:
                logger.info(
                    "Vault has already been initialized, establishing quorum instead"
                )
                return status_init  # Return status_init to establish quorum

            logger.info("Going to init and unseal Vault")
            try:
                delete_secret([root_token, vault_keys])
            except kubernetes.client.exceptions.ApiException as delete_secret_error:
                logger.error(
                    "During  initialize got a error -> {}", delete_secret_error
                )
            create_secrets(init_vault(vault_instance_url))

            logger.info("Unsealing Vault node {}", replica_url)
            read_secret(vault_keys, vault_instance_url)

            return status_init
        if get_seal.json()["sealed"]:
            logger.info("Unsealing Vault node {}", replica_url)
            read_secret(vault_keys, vault_instance_url)

            return status_unseal
    except requests.exceptions.ConnectionError as seal_status_error:
        logger.info("Unexpected status -> {}", seal_status_error)
        return status_error

    return status_ok


def delete_secret(secret_name):
    for secret in secret_name:
        secret_for_delete = api_instance.delete_namespaced_secret(
            name=secret, namespace=namespace
        )
        logger.info("Secret {} has been deleted", secret_for_delete.details.name)


def get_quorum_established(quorum_established, replica_list, main_url):
    while not quorum_established:
        quorum_established = True
        for vault_instance_url in replica_list:
            if vault_instance_url == main_url:
                continue

            leader_status = requests.get(
                f"{vault_instance_url}/v1/sys/leader", verify=False  # nosec
            )

            if "leader_address" not in leader_status.json():
                quorum_established = False
                logger.info(
                    "Vault node {} is not ready: {} ", replica_url, leader_status.json()
                )
                continue
            if leader_status.json()["leader_address"] == main_url:
                logger.info(
                    "Vault node {} has acknowledged {} as the leader",
                    vault_instance_url,
                    main_url,
                )
            else:
                logger.info(
                    "Vault node {} has not acknowledged {} as the leader",
                    vault_instance_url,
                    main_url,
                )

                quorum_established = False
                break

        sleep(5)


def wait_for_quorum(replica_list, main_url):
    payload = {"leader_api_addr": main_url}
    leader_status = requests.get(f"{main_url}/v1/sys/leader", verify=False)  # nosec
    logger.info(
        "Leader http code {}, response json {}",
        leader_status.status_code,
        leader_status.json(),
    )
    for vault_instance_url in replica_list:
        if vault_instance_url == main_url:
            continue
        try:
            logger.info("Joining {} to leader", vault_instance_url)

            requests.post(
                f"{vault_instance_url}/v1/sys/storage/raft/join",
                data=json.dumps(payload),
                verify=False,  # nosec
            )

        except requests.exceptions.ConnectionError as connection_error:
            logger.info("Unexpected error {}", connection_error)
            return status_error

        logger.info("Unsealing {}", replica_url)
        read_secret(vault_keys, vault_instance_url)

    quorum_established = False

    get_quorum_established(
        quorum_established=quorum_established,
        replica_list=replica_list,
        main_url=main_url,
    )

    logger.info("Quorum has been established with {} as the leader", main_url)


if __name__ == "__main__":

    vault_initialized = False
    leader_url = ""
    secret_shares = ""  # nosec
    secret_threshold = ""  # nosec
    namespace = ""
    root_token = ""  # nosec
    vault_keys = ""  # nosec
    scan_delay = ""
    vault_url = ""
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
            print("Please check system variable {}", error)
            exit(2)
    logger.remove()
    logger.add(sys.stderr, format=tracing_formatter)
    logger.info("Start Vault auto unseal")
    k8s_client = get_kubernetes_client()
    api_instance = k8s_client.CoreV1Api()
    k8s_secret = k8s_client.V1Secret()
    status_init = 0
    status_unseal = 1
    status_ok = 2
    status_error = 3
    auto_unseal_payload = {
        "secret_shares": int(secret_shares),
        "secret_threshold": int(secret_threshold),
    }

    url = urlparse(vault_url)
    vault_hostname = url.hostname
    vault_port = url.port
    vault_namespace = url.hostname.split(".")[1]
    pods = api_instance.list_namespaced_pod(
        namespace=vault_namespace, label_selector="vault-sealed=true"
    )
    logger.info("Vault Hostname: {} Vault Port: {}", vault_hostname, vault_port)

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
            vault_replicas = sorted(
                [
                    f"{url.scheme}://{x[4][0]}:{x[4][1]}"
                    for x in socket.getaddrinfo(
                        vault_hostname, vault_port, proto=socket.IPPROTO_TCP
                    )
                ]
            )
        except socket.gaierror as err:
            logger.error("Failed to lookup DNS info: {}", err)
            sleep(5)
            continue
        vault_replicas.clear()
        for pod in pods.items:
            vault_replicas.append(f"{url.scheme}://{pod.status.pod_ip}:{vault_port}")
        logger.info("Discovered Vault instance(s): {}", vault_replicas)
        for replica_url in vault_replicas:
            status = get_seal_status(replica_url, vault_initialized)
            if status == status_init:
                if len(vault_replicas) > 1:
                    logger.info(
                        "Vault running in High Availability mode will unseal Vault nodes one by one"
                    )
                else:
                    logger.info("Vault running in Singe Node mode will unseal")
                # Only set the Leader URL once
                if not vault_initialized:
                    vault_initialized = True
                    leader_url = replica_url
                logger.info(
                    "Vault was just initialized, waiting for quorum to be established"
                )
                wait_for_quorum(vault_replicas, leader_url)

            if status == status_unseal:
                # If we've unsealed an instance, then by definition vault has been initialized
                vault_initialized = True
                logger.info("Vault has been unsealed")

        sleep(scan_delay)
