#!/bin/bash

# Step 1: Define the contract name and output path
CONTRACT_NAME="ExocoreBtcGateway"
OUTPUT_PATH="/Users/will/go/src/github.com/ExocoreNetwork/bridge_private"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
CLIENT_CHAIN_ID=111

# Step 2: Update ABI
forge inspect src/core/$CONTRACT_NAME.sol:$CONTRACT_NAME abi > $OUTPUT_PATH/src/abi/exocorebtcgateway.json

# Step 3: Flatten the contract and filter out compiler log information
forge flatten src/core/ExocoreBtcGateway.sol | grep -v "Compiling" | grep -v "Solc" | grep -v "Compiler run" > src/core/ExocoreBtcGatewayFlatten.sol

# Step 4: Deploy the contract and capture the output
output=$(forge create --rpc-url http://127.0.0.1:8546 \
    --private-key "$PRIVATE_KEY" \
    src/core/ExocoreBtcGatewayFlatten.sol:ExocoreBtcGateway)

# Step 5: Extract the contract address from the output
contract_address=$(echo "$output" | grep "Deployed to:" | awk '{print $3}')

# Step 6: Update the CONTRACT_ADDRESS in the .env file
sed -i "" "s/^CONTRACT_ADDRESS=.*/CONTRACT_ADDRESS=\"$contract_address\"/" $OUTPUT_PATH/.env

# Step 7: Output the deployment information
echo "$output"

# Step 8: Send a transaction to register an address
cast send --rpc-url http://127.0.0.1:8546 \
    --private-key "$PRIVATE_KEY" \
    $contract_address \
    "registerAddress(bytes,bytes)" \
    0x74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d68 \
    0x307837303939373937304335313831326463334130313043376430316235306530643137646337394338

# Step 9: Call the btcToExocoreAddress function
cast call --rpc-url http://127.0.0.1:8546 \
    $contract_address \
    "btcToExocoreAddress(bytes)(bytes)" \
    0x74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d68

# Step 10: Send a transaction to deposit to an address
cast send --rpc-url http://127.0.0.1:8546 \
    --private-key "$PRIVATE_KEY" \
    --gas-limit 1000000 \
    0x0000000000000000000000000000000000000804 \
    "depositTo(uint32,bytes,bytes,uint256)" \
    ${CLIENT_CHAIN_ID} \
    0x2260fac5e5542a773aa44fbcfedf7c193bc2c599000000000000000000000000 \
    0x74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d68 \
    2222

# Step 11: Call the getPrincipalBalance function
cast call --rpc-url http://127.0.0.1:8546 \
    0x0000000000000000000000000000000000000804 \
    "getPrincipalBalance(uint32,bytes,bytes)(uint256)" \
    ${CLIENT_CHAIN_ID} \
    0x2260fac5e5542a773aa44fbcfedf7c193bc2c599000000000000000000000000 \
    0x74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d68
