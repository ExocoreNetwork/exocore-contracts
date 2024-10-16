#!/usr/bin/env python

import json
import subprocess
import pandas as pd
import os
from compare_storage_layout import parse_output, compare_layouts, get_current_layout

def get_deployed_addresses():
    with open('script/deployedContracts.json', 'r') as f:
        data = json.load(f)
    return {
        'Bootstrap': data['clientChain'].get('bootstrapLogic'),
        'ClientChainGateway': data['clientChain'].get('clientGatewayLogic'),
        'Vault': data['clientChain'].get('vaultImplementation'),
        'RewardVault': data['clientChain'].get('rewardVaultImplementation'),
        'ExoCapsule': data['clientChain'].get('capsuleImplementation')
    }

def get_storage_layout(contract_name, address, rpc_url):
    if not address:
        print(f"Skipping {contract_name} as it's not deployed.")
        return pd.DataFrame()
    
    result = subprocess.run(['cast', 'storage', address, '--rpc-url', rpc_url], capture_output=True, text=True)
    print(f"finish executing: cast storage {address} --rpc-url ...")

    if result.returncode != 0:
        raise Exception(f"Error getting current layout for {contract_name}: {result.stderr}")

    return parse_output(contract_name, result.stdout.split('\n'))

def load_and_parse_layout(contract_name, path):
    with open(path, 'r') as f:
        lines = f.readlines()
        return parse_output(contract_name, lines)

if __name__ == "__main__":
    try:
        api_key = os.environ.get('ALCHEMY_API_KEY')
        if not api_key:
            raise ValueError("ALCHEMY_API_KEY environment variable is not set")
        
        # Construct the RPC URL for Sepolia
        rpc_url = f"https://eth-sepolia.g.alchemy.com/v2/{api_key}"

        addresses = get_deployed_addresses()
        all_mismatches = {}

        for contract_name, address in addresses.items():
            print(f"Checking {contract_name}...")
            deployed_layout = get_storage_layout(contract_name, address, rpc_url)
            if deployed_layout.empty:
                print(f"No deployed layout found for {contract_name}.")
                continue
            
            current_layout = get_current_layout(contract_name)
            if current_layout.empty:
                raise ValueError(f"Error: No valid entries of current layout found for {contract_name}.")
            
            mismatches = compare_layouts(deployed_layout, current_layout)
            if mismatches:
                all_mismatches[contract_name] = mismatches
        
        # then we load the layout file of ExocoreGateway on target branch and compare it with the current layout
        print("Checking ExocoreGateway...")
        target_branch_layout = load_and_parse_layout('ExocoreGateway', 'ExocoreGateway_target.txt')
        current_layout = get_current_layout('ExocoreGateway')
        mismatches = compare_layouts(target_branch_layout, current_layout)
        if mismatches:
            all_mismatches['ExocoreGateway'] = mismatches

        if all_mismatches:
            print("Mismatches found for current contracts:")
            for contract, mismatches in all_mismatches.items():
                print(f"{contract}:")
                for mismatch in mismatches:
                    print(f"  {mismatch}")
            exit(1)
        else:
            print("Storage layout is compatible with all deployed contracts.")
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
