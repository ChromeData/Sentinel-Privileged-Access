.PHONY: help validate deploy simulate destroy
.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

validate: ## Schema-check every detection before deploying or submitting
	python3 scripts/validate.py

deploy: ## Deploy rules to your LAB Sentinel workspace (needs WORKSPACE_ID)
	@test -n "$(WORKSPACE_ID)" || { echo "set WORKSPACE_ID=<lab workspace>"; exit 1; }
	pwsh -File scripts/deploy-rules.ps1 -WorkspaceId "$(WORKSPACE_ID)"

simulate: ## Generate the activity each rule targets, to prove they fire
	pwsh -File scripts/simulate-activity.ps1

destroy: ## Remove the deployed lab rules
	@test -n "$(WORKSPACE_ID)" || { echo "set WORKSPACE_ID"; exit 1; }
	pwsh -File scripts/deploy-rules.ps1 -WorkspaceId "$(WORKSPACE_ID)" -Remove
