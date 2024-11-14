#!/usr/bin/env bash

# Get the directory of the script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Fetch the validator details and save them to container.json
curl -s -X GET "http://localhost:3500/eth/v1/beacon/states/head/validators/0x98db81971df910a5d46314d21320f897060d76fdf137d22f0eb91a8693a4767d2a22730a3aaa955f07d13ad604f968e9" -H "accept: application/json" | jq >"$SCRIPT_DIR/container.json"

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

# # Wait till the slot is reached
# seconds_per_slot=$(jq -r .data.SECONDS_PER_SLOT "$SCRIPT_DIR/spec.json")
# while true; do
#     current_slot=$(curl http://localhost:3500/eth/v1/beacon/headers | jq -r '.data[0].header.message.slot')
#     if (( current_slot > slot )); then
#         break
#     fi
#     echo "Waiting for slot $slot, current slot is $current_slot"
#     sleep $seconds_per_slot
# done

# Now derive the proof using the proof generation binary, which must already be running configured to the localnet
curl -X POST -H "Content-Type: application/json" \
	-d "{\"slot\": $slot, \"validator_index\": $validator_index}" \
	http://localhost:8989/v1/validator-proof | jq >"$SCRIPT_DIR/proof.json"

forge script script/integration/2_VerifyDepositNST.s.sol --skip-simulation \
	--rpc-url $CLIENT_CHAIN_RPC --broadcast \
	--evm-version cancun # required, otherwise you get EvmError: NotActivated
