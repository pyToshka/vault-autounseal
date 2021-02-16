# vault-auto-unseal

## What for

As You know Vault provide several mechanisms for Auto unseal,
but sometimes I couldn't use AWS or GCP as cloud provider.
Main idea was use Kubernetes secretes as source for auto unseal.

## Dependencies

- Kubernetes
- Python > 3.7

## How to use

Checkout source code from the repository

Install dependencies  via pip: `pip install -r requirements.txt`

Setup system environment

Run script `python app.py`

## System environments

| Name                    | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| VAULT_URL               | Vault server url with port e.g http://127.0.0.1:8200         |
| VAULT_SECRET_SHARES     | Specifies the number of shares that should be encrypted by the HSM and stored for auto-unsealing. Currently must be the same as `secret_shares` |
| VAULT_SECRET_THRESHOLD  | Specifies the number of shares required to reconstruct the recovery key. This must be less than or equal to `recovery_shares`. |
| NAMESPACE               | Kubernetes namespace for storing vault root key and keys     |
| VAULT_ROOT_TOKEN_SECRET | Kubernetes secret name for root token                        |
| VAULT_KEYS_SECRET       | Kubernetes secret name for vault key                         |

## Deployment

The solution can be run as docker container or inside Kubernetes

Building docker container

```shell
docker build . -t vault-autounseal:latest

```

or You can pull existing image from DockerHub

```shell
docker pull kennyopennix/vault-autounseal:latest
```
