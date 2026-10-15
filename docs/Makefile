# Copyright (c) 2025-2026 Datalayer, Inc.
# Distributed under the terms of the Modified BSD License.

# Copyright (c) Datalayer, Inc. https://datalayer.io
# Distributed under the terms of the MIT License.

SHELL=/bin/bash

.DEFAULT_GOAL := default

CONDA_ACTIVATE=source $$(conda info --base)/etc/profile.d/conda.sh ; conda activate
CONDA_DEACTIVATE=source $$(conda info --base)/etc/profile.d/conda.sh ; conda deactivate
CONDA_REMOVE=source $$(conda info --base)/etc/profile.d/conda.sh ; conda remove -y --all -n

ENV_NAME=datalayer

.SILENT: init install

.PHONY: build publish

help: ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

default: help ## default target is help

env-rm:
	-conda remove -y --all -n ${ENV_NAME}

env:
	-conda env create -f environment.yml
	@echo 
	@echo --------------------------------------------------
	@echo ✨  Datalayer environment is created.
	@echo --------------------------------------------------
	@echo

clean: ## clear
	($(CONDA_ACTIVATE) ${ENV_NAME}; \
	  npm clear )

install: ## install
	($(CONDA_ACTIVATE) ${ENV_NAME}; \
	  npm install )

start: ## start
	($(CONDA_ACTIVATE) ${ENV_NAME}; \
	  npm start )

build: ## build
	($(CONDA_ACTIVATE) ${ENV_NAME}; \
	  npm run build )

# The bucket and the distribution of agent-shield.datalayer.tech. Neither
# exists yet (checked 2026-10-15 in account 773842031886: the bucket answers
# 404, the name has no DNS record); the distribution id is taken from the
# environment so that no other site's is ever invalidated by mistake.
BUCKET ?= datalayer-agent-shield
DISTRIBUTION ?= $(AGENT_SHIELD_CLOUDFRONT_DISTRIBUTION)

generate: ## write the generated pages (the policy reference, the register, the Python API)
	python scripts/generate.py

check: ## hold every page to what is built
	python scripts/generate.py --check && python scripts/check_pages.py

deploy: build ## deploy to the bucket and invalidate the distribution
	@test -n "$(DISTRIBUTION)" || (echo "set AGENT_SHIELD_CLOUDFRONT_DISTRIBUTION to the distribution of agent-shield.datalayer.tech" && exit 1)
	($(CONDA_ACTIVATE) ${ENV_NAME}; \
	  aws s3 rm \
		s3://$(BUCKET)/ \
		--recursive && \
	  aws s3 cp \
		./build \
		s3://$(BUCKET)/ \
		--recursive && \
	  aws cloudfront create-invalidation \
		--distribution-id $(DISTRIBUTION) \
		--paths "/*" )
	echo open ✨  https://agent-shield.datalayer.tech
