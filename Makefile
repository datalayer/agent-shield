# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

SHELL=/bin/bash

.DEFAULT_GOAL := default

.PHONY: clean build test

VERSION = "0.0.3"

default: all ## Default target is all.

help: ## display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

all: clean dev ## Clean Install and Build

install:
	pip install .

dev:
	pip install ".[test,lint,typing]"

build:
	pip install build
	python -m build .

clean: ## clean
	git clean -fdx

clean-npm: ## clean-npm
	npm run clean

build-npm: ## build-npm
	npm run build

build-lib: ## build-lib
	npm run build:lib

warning:
	echo "\x1b[34m\x1b[43mEnsure you have run \x1b[1;37m\x1b[41m conda deactivate \x1b[22m\x1b[34m\x1b[43m before invoking this.\x1b[0m"

publish-npm: clean-npm build-lib ## publish-npm
	npm publish
	echo open https://www.npmjs.com/package/@datalayer/agent-shield --public

test: ## Run tests
	python -m pytest tests/ -v

start-agent: ## Start the MCP agent CLI (stdio server). Usage: make start-agent [MODEL=<model>]
	python examples/agent/agent_cli.py $(if $(MODEL),--model $(MODEL),)

start-agent-shield: ## Start the Agent Shield agent CLI (stdio server). Usage: make start-agent-shield [MODEL=<model>]
	python examples/agent/agent_cli.py --codemode $(if $(MODEL),--model $(MODEL),)

build-docker:
	docker buildx build --platform linux/amd64,linux/arm64 -t datalayer/agent-shield:${VERSION} .
	docker image tag datalayer/agent-shield:${VERSION} datalayer/agent-shield:latest

start-docker:
	docker run -i --rm \
	  -e SERVER_URL=http://localhost:8888 \
	  -e TOKEN=MY_TOKEN \
	  -e NOTEBOOK_PATH=notebook.ipynb \
	  --network=host \
	  datalayer/agent-shield:latest

pull-docker:
	docker image pull datalayer/agent-shield:latest

push-docker:
	docker push datalayer/agent-shield:${VERSION}
	docker push datalayer/agent-shield:latest

claude-linux:
	NIXPKGS_ALLOW_UNFREE=1 nix run github:k3d3/claude-desktop-linux-flake \
		--impure \
		--extra-experimental-features flakes \
		--extra-experimental-features nix-command

jupyterlab:
	pip uninstall -y pycrdt datalayer_pycrdt
	pip install datalayer_pycrdt
	jupyter lab \
		--port 8888 \
		--ip 0.0.0.0 \
		--ServerApp.root_dir ./dev/content \
		--IdentityProvider.token MY_TOKEN

publish-pypi: # publish the pypi package
	git clean -fdx && \
		python -m build
	@exec echo
	@exec echo twine upload ./dist/*-py3-none-any.whl
	@exec echo
	@exec echo https://pypi.org/project/datalayer-agent-shield/#history
