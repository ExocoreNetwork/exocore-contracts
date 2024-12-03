#!/usr/bin/env bash

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Check that all of the variables required exist.
vars=(
	CLIENT_CHAIN_RPC
	INTEGRATION_BEACON_CHAIN_ENDPOINT
	INTEGRATION_NST_DEPOSITOR
	INTEGRATION_PROVE_ENDPOINT
	INTEGRATION_PUBKEY
)
for var in "${vars[@]}"; do
	if [ -z "${!var}" ]; then
		echo "Error: $var must be set"
		exit 1
	fi
done

# Check for the files to exist
if [ ! -f "$SCRIPT_DIR/spec.json" ]; then
	echo "Error: spec.json not found in $SCRIPT_DIR"
	exit 1
fi

# Fetch the validator details and save them to container.json
curl -s -X GET \
	"$INTEGRATION_BEACON_CHAIN_ENDPOINT/eth/v1/beacon/states/head/validators/$INTEGRATION_PUBKEY" \
	-H "accept: application/json" | jq >"$SCRIPT_DIR/container.json"

# Ensure the request was successful
if [ $? -ne 0 ]; then
	echo "Error: Failed to fetch validator details."
	exit 1
fi

# Fetch slots per epoch from the spec
slots_per_epoch=$(jq -r .data.SLOTS_PER_EPOCH "$SCRIPT_DIR/spec.json")

# Ensure slots_per_epoch was fetched successfully
if [ -z "$slots_per_epoch" ]; then
	echo "Error: Failed to fetch SLOTS_PER_EPOCH."
	exit 1
fi

# Extract the validator index and activation epoch from container.json
validator_index=$(jq -r .data.index "$SCRIPT_DIR/container.json")
epoch=$(jq -r .data.validator.activation_eligibility_epoch "$SCRIPT_DIR/container.json")

# Ensure epoch value is valid
if [ -z "$epoch" ] || [ "$epoch" == "null" ]; then
	echo "Error: Activation epoch not found for the validator."
	exit 1
fi

# Calculate the slot number
slot=$((slots_per_epoch * epoch))

# Now derive the proof using the proof generation binary, which must already be running configured to the localnet
response=$(curl -s -w "%{http_code}" -X POST -H "Content-Type: application/json" \
	-d "{\"slot\": $slot, \"validator_index\": $validator_index}" \
	$INTEGRATION_PROVE_ENDPOINT/v1/validator-proof)

http_code=${response: -3}
body=${response:0:${#response}-3}

if [ "$http_code" != "200" ]; then
	echo "Error: Failed to generate proof. HTTP code: $http_code"
	echo "Response: $body"
	exit 1
fi

echo "$body" | jq . >"$SCRIPT_DIR/proof.json"

if [ ! -s "$SCRIPT_DIR/proof.json" ]; then
	echo "Error: Generated proof is empty"
	exit 1
fi

export INTEGRATION_NST_DEPOSITOR=$INTEGRATION_NST_DEPOSITOR
forge script script/integration/2_VerifyDepositNST.s.sol --skip-simulation \
	--rpc-url $CLIENT_CHAIN_RPC --broadcast \
	--evm-version cancun # required, otherwise you get EvmError: NotActivated
