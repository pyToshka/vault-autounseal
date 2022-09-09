all: docker

docker:
	docker buildx build -t vault-autounseal:local --platform linux/arm64,linux/amd64 .

helm_template:
	helm template -n vault-autounseal vault-autounseal charts/vault-autounseal --set=settings.vault_url=http://vault.vault:8200

helm_install:
	helm upgrade --install --create-namespace -n vault-autounseal vault-autounseal charts/vault-autounseal --set=settings.vault_url=http://vault.vault:8200
	kubectl rollout restart deployment vault-autounseal -n vault-autounseal

helm_install_vault:
	helm repo add hashicorp https://helm.releases.hashicorp.com
	helm repo update
	helm install --create-namespace -n vault vault hashicorp/vault

get_root_token:
	kubectl get secret -n vault-autounseal vault-root-token  -o json | jq -r '.data.root_token' | base64 -d
