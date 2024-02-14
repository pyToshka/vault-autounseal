.PHONY: help
help: ## Help for usage
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
all: docker
docker: ## Build docker image for local usage
	docker buildx build -t vault-autounseal:local --platform linux/arm64,linux/amd64 .

helm_template:  ## Locally render templates for chart
	helm template -n vault-autounseal vault-autounseal charts/vault-autounseal --set=settings.vault_url=http://vault.vault:8200

helm_install: ## Install Vault auto-unseal helm chart
	helm upgrade --install --create-namespace -n vault-autounseal vault-autounseal charts/vault-autounseal --set=settings.vault_url=http://vault.vault:8200
	kubectl rollout restart deployment vault-autounseal -n vault-autounseal

helm_install_vault:  ## Install Vault chart
	helm repo add hashicorp https://helm.releases.hashicorp.com
	helm repo update
	helm install --create-namespace -n vault vault hashicorp/vault

get_root_token: ## Get Vault root token
	kubectl get secret -n vault-autounseal vault-root-token  -o json | jq -r '.data.root_token' | base64 -d

kind_m1: ## Run kind kubernetes cluster ARM
	DOCKER_DEFAULT_PLATFORM='linux/arm64' kind create cluster --config tests/kind.yml

kind: ## Run kind kubernetes cluster X86
	kind create cluster --config tests/kind.yml

deploy_local_m1: kind_m1 ## Deploy auto-unseal to kind ARM, Vault ha mode disabled
	helm install --create-namespace -n vault vault hashicorp/vault
	helm upgrade --install --create-namespace -n vault-autounseal  --set=settings.vault_url=http://vault.vault:8200 vault-autounseal charts/vault-autounseal/

deploy_local_kind: kind ## Deploy auto-unseal to kind x86, Vault ha mode disabled
	helm upgrade --install --create-namespace -n vault vault hashicorp/vault
	helm upgrade --install --create-namespace -n vault-autounseal  --set=settings.vault_url=http://vault.vault:8200 vault-autounseal charts/vault-autounseal/

delete_local_kind: ## Delete kind cluster
	kind delete cluster -n vault

run_local_crc_single: ## Deploy to RedHat CRC Vault single
	helm upgrade --install --create-namespace -n vault vault hashicorp/vault --set "global.openshift=true"
	helm upgrade --install --create-namespace -n vault-autounseal  --set=settings.vault_url=http://vault.vault:8200 vault-autounseal charts/vault-autounseal/

run_local_ha: ## Deploy helm charts to current context Vault Ha Mode
	helm upgrade --install --create-namespace -n vault vault hashicorp/vault --set "global.openshift=true" --set="server.ha.enabled=true" --set="server.ha.raft.enabled=true"
	helm upgrade --install --create-namespace -n vault-autounseal  --set=settings.vault_url=http://vault.vault:8200 vault-autounseal charts/vault-autounseal/

uninstall_chart: ## Uninstall helm charts from current context
	helm uninstall  -n vault vault || true
	helm uninstall  -n vault-autounseal vault-autounseal || true
	kubectl delete ns vault || true
	kubectl delete ns vault-autounseal || true
