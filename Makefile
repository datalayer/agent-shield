# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

SHELL=/bin/bash

.DEFAULT_GOAL := default

.PHONY: clean build test test-ts tck dev install

default: all ## Default target is all.

help: ## display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

all: clean dev ## Clean Install and Build

install:
	pip install .

dev:
	pip install -e ".[test,lint,typing]"

build:
	pip install build
	python -m build .

clean: ## clean
	git clean -fdx

test: ## Run the Python tests
	python -m pytest tests/ -q

test-ts: ## Run the TypeScript tests (builds lib/ first)
	npm install --no-audit --no-fund && npm test

tck: ## Run the ACP Test Compatibility Kit against the proxy in front of the fake agent
	mkdir -p /tmp/agent-shield-tck && agent-shield policy init --force /tmp/agent-shield-tck/agent-shield.yaml
	acp-tck --agent-cwd /tmp/agent-shield-tck --timeout 20 --test-timeout 60 -- agent-shield run --policy /tmp/agent-shield-tck/agent-shield.yaml -- python tests/fixtures/fake_agent.py

build-lib: ## build-lib
	npm run build:lib

publish-npm: build-lib ## publish-npm
	npm publish
	echo open https://www.npmjs.com/package/@datalayer/agent-shield --public

publish-pypi: # publish the pypi package
	git clean -fdx && \
		python -m build
	@exec echo
	@exec echo twine upload ./dist/*-py3-none-any.whl
	@exec echo
	@exec echo https://pypi.org/project/datalayer-agent-shield/#history
