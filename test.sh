#!/bin/bash

# Flatten the contract and filter out compiler log information
forge flatten src/core/ExocoreBtcGateway.sol | grep -v "Compiling" | grep -v "Solc" | grep -v "Compiler run" > src/core/ExocoreBtcGatewayFlatten.sol

# Deploy the contract and capture the output
output=$(forge create --rpc-url http://127.0.0.1:8546 \
    --constructor-args "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" \
    --private-key "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" \
    src/core/ExocoreBtcGatewayFlatten.sol:ExocoreBtcGateway)

# Extract the contract address from the output
contract_address=$(echo "$output" | grep "Deployed to:" | awk '{print $3}')

# Update the CONTRACT_ADDRESS in the .env file
sed -i "" "s/^CONTRACT_ADDRESS=.*/CONTRACT_ADDRESS=\"$contract_address\"/" /Users/will/go/src/github.com/ExocoreNetwork/bridge_private/.env

# Output the deployment information
echo "$output"

# Send a transaction to register an address
cast send --rpc-url http://127.0.0.1:8546 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    $contract_address \
    "registerAddress(bytes,bytes)" \
    0x74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d68 \
    0x307837303939373937304335313831326463334130313043376430316235306530643137646337394338

# Call the btcToExocoreAddress function
cast call --rpc-url http://127.0.0.1:8546 \
    $contract_address \
    "btcToExocoreAddress(bytes)(bytes)" \
    0x74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d68

# Send a transaction to deposit to an address
cast send --rpc-url http://127.0.0.1:8546 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --gas-limit 1000000 \
    0x0000000000000000000000000000000000000804 \
    "depositTo(uint32,bytes,bytes,uint256)" \
    1 \
    0x0000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c599 \
    0x74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d68 \
    2222

# Call the getPrincipalBalance function
cast call --rpc-url http://127.0.0.1:8546 \
    0x0000000000000000000000000000000000000804 \
    "getPrincipalBalance(uint32,bytes,bytes)(uint256)" \
    1 \
    0x0000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c599 \
    0x74623170647766356172306b787232736468787732387771686a777a796e7a6c6b6472716c6778386a753373723032686b6c64716d6c6673706d306d6d68
