#!/usr/bin/env bash

set -e

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Check that all of the variables required exist.
vars=(
	CLIENT_CHAIN_RPC
	INTEGRATION_BEACON_CHAIN_ENDPOINT
	INTEGRATION_CONTRACT_DEPLOYER
	INTEGRATION_DEPOSIT_DATA_ROOT
	INTEGRATION_NST_DEPOSITOR
	INTEGRATION_PUBKEY
	INTEGRATION_SIGNATURE
	INTEGRATION_STAKERS
	INTEGRATION_TOKEN_DEPLOYERS
	INTEGRATION_VALIDATOR_KEYS
)
for var in "${vars[@]}"; do
	if [ -z "${!var}" ]; then
		echo "Error: $var must be set"
		exit 1
	fi
done

# Fetch the validator details and save them to container.json
if ! curl -s -X GET "$INTEGRATION_BEACON_CHAIN_ENDPOINT/eth/v1/beacon/genesis" -H "accept: application/json" | jq . >"$SCRIPT_DIR/genesis.json"; then
	echo "Error: Failed to fetch genesis data from the beacon chain"
	exit 1
fi

if ! jq -e .data "$SCRIPT_DIR/genesis.json" >/dev/null; then
	echo "Error: Invalid genesis data structure."
	exit 1
fi

# Fetch the spec sheet and save it to spec.json
if ! curl -s -X GET "$INTEGRATION_BEACON_CHAIN_ENDPOINT/eth/v1/config/spec" | jq >"$SCRIPT_DIR/spec.json"; then
	echo "Error: Failed to fetch spec data from the beacon chain"
	exit 1
fi

if ! jq -e .data "$SCRIPT_DIR/spec.json" >/dev/null; then
	echo "Error: Invalid spec data structure."
	exit 1
fi

timestamp=$(jq -r .data.genesis_time "$SCRIPT_DIR/genesis.json")
private_key=$INTEGRATION_NST_DEPOSITOR
sender=$(cast wallet a $private_key)
if [ $? -ne 0 ]; then
	echo "Error: Failed to derive sender address."
	exit 1
fi
deposit_address=$(jq -r .data.DEPOSIT_CONTRACT_ADDRESS "$SCRIPT_DIR/genesis.json")
slots_per_epoch=$(jq -r .data.SLOTS_PER_EPOCH "$SCRIPT_DIR/spec.json")
if ! [[ "$slots_per_epoch" =~ ^[0-9]+$ ]]; then
    echo "Error: Invalid slots per epoch"
    exit 1
fi
seconds_per_slot=$(jq -r .data.SECONDS_PER_SLOT "$SCRIPT_DIR/spec.json")
if ! [[ "$seconds_per_slot" =~ ^[0-9]+$ ]]; then
    echo "Error: Invalid seconds per slot"
    exit 1
fi

# Make the variables available to the forge script
export INTEGRATION_VALIDATOR_KEYS=$INTEGRATION_VALIDATOR_KEYS
export INTEGRATION_STAKERS=$INTEGRATION_STAKERS
export INTEGRATION_TOKEN_DEPLOYERS=$INTEGRATION_TOKEN_DEPLOYERS
export INTEGRATION_CONTRACT_DEPLOYER=$INTEGRATION_CONTRACT_DEPLOYER
export INTEGRATION_PUBKEY=$INTEGRATION_PUBKEY
export INTEGRATION_SIGNATURE=$INTEGRATION_SIGNATURE
export INTEGRATION_DEPOSIT_DATA_ROOT=$INTEGRATION_DEPOSIT_DATA_ROOT
export INTEGRATION_BEACON_GENESIS_TIMESTAMP=$timestamp
# Since the devnet uses `--fork=deneb` and `DENEB_FORK_EPOCH: 0`, the deneb time is equal to the beacon genesis time
export INTEGRATION_DENEB_TIMESTAMP=$timestamp
export INTEGRATION_SECONDS_PER_SLOT=$seconds_per_slot
export INTEGRATION_SLOTS_PER_EPOCH=$slots_per_epoch
export INTEGRATION_DEPOSIT_ADDRESS=$deposit_address
export INTEGRATION_NST_DEPOSITOR=$INTEGRATION_NST_DEPOSITOR
export SENDER=$sender

# Specify SENDER so that libraries can be deployed
# Use Cancun version because prove.sh needs it or it complains
# Better to recompile here than to recompile in prove.sh
forge script \
	--skip-simulation script/integration/1_DeployBootstrap.s.sol \
	--rpc-url $CLIENT_CHAIN_RPC \
	--broadcast -v \
	--sender $SENDER \
	--evm-version cancun
