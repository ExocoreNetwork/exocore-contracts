#!/usr/bin/env bash

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Fetch the validator details and save them to container.json
curl -s -X GET "http://localhost:3500/eth/v1/beacon/genesis" -H "accept: application/json" | jq >"$SCRIPT_DIR/genesis.json"

# Fetch the spec sheet and save it to spec.json
curl -s http://localhost:3500/eth/v1/config/spec | jq >"$SCRIPT_DIR/spec.json"

# Ensure the request was successful
if [ $? -ne 0 ]; then
	echo "Error: Failed to fetch genesis data of the beacon chain."
	exit 1
fi

timestamp=$(jq -r .data.genesis_time "$SCRIPT_DIR/genesis.json")
private_key=${NST_DEPOSITOR:-"0x47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd"}
sender=$(cast wallet a $private_key)
deposit_address=$(jq -r .data.DEPOSIT_CONTRACT_ADDRESS "$SCRIPT_DIR/genesis.json")
slots_per_epoch=$(jq -r .data.SLOTS_PER_EPOCH "$SCRIPT_DIR/spec.json")
seconds_per_slot=$(jq -r .data.SECONDS_PER_SLOT "$SCRIPT_DIR/spec.json")

# Since the devnet uses `--fork=deneb` and `DENEB_FORK_EPOCH: 0`, the deneb time is equal to the beacon genesis time
export INTEGRATION_BEACON_GENESIS_TIMESTAMP=$timestamp
export INTEGRATION_DENEB_TIMESTAMP=$timestamp
export INTEGRATION_SECONDS_PER_SLOT=$seconds_per_slot
export INTEGRATION_SLOTS_PER_EPOCH=$slots_per_epoch
export INTEGRATION_DEPOSIT_ADDRESS=$deposit_address
export SENDER=$sender

forge script \
	--skip-simulation script/integration/1_DeployBootstrap.s.sol \
	--rpc-url $CLIENT_CHAIN_RPC \
	--broadcast -vvvv \
	--sender $SENDER \
	--evm-version cancun
