.PHONY: help validate deploy simulate destroy
.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

kusto: ## Start the local Kusto engine, so the detections can actually be run
	docker run -d --name kustainer -e ACCEPT_EULA=Y -m 4G -p 8080:8080 	  mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
	@echo "waiting for Kusto..."
	@until curl -s -o /dev/null -X POST http://localhost:8080/v1/rest/mgmt 	  -H "Content-Type: application/json" -d '{"csl":".show version"}'; do sleep 5; done
	@echo "ready. now run: make test-live"

test-live: ## Execute every detection against Kusto with true positives and decoys
	python -m pytest tests/test_detections_execute.py -v

kusto-stop: ## Tear down the local Kusto engine
	-docker rm -f kustainer

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
