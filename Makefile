# Makefile for Foundry commands

# Variables
FOUNDRY_PROFILE=test

# Targets
.PHONY: test build fmt

test:
	FOUNDRY_PROFILE=$(FOUNDRY_PROFILE) forge test -vvv

build:
	forge build

fmt:
	forge fmt
