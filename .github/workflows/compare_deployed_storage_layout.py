#!/usr/bin/env python

import json
import subprocess
import os
from compare_storage_layout import parse_layout, compare_layouts

def get_deployed_addresses():
    with open('script/deployedContracts.json', 'r') as f:
        data = json.load(f)
    return {
        'Bootstrap': data['clientChain'].get('bootstrap'),
        'ClientChainGateway': data['clientChain'].get('clientGatewayLogic'),
        'ExocoreGateway': data['exocore'].get('exocoreGatewayLogic'),
        'Vault': data['clientChain'].get('vaultImplementation'),
        'RewardVault': data['clientChain'].get('rewardVaultImplementation'),
        'ExoCapsule': data['clientChain'].get('capsuleImplementation')
    }

def get_storage_layout(contract_name, address):
    if not address:
        print(f"Skipping {contract_name} as it's not deployed.")
        return None
    api_key = os.environ.get('ALCHEMY_API_KEY')
    if not api_key:
        raise ValueError("ALCHEMY_API_KEY environment variable is not set")
    
    # Construct the RPC URL for Sepolia
    rpc_url = f"https://eth-sepolia.g.alchemy.com/v2/{api_key}"
    
    result = subprocess.run(['cast', 'storage', address, '--rpc-url', rpc_url], capture_output=True, text=True)
    with open(f'{contract_name}_deployed.md', 'w') as f:
        f.write(result.stdout)
    return parse_layout(f'{contract_name}_deployed.md')

def get_current_layout(contract_name):
    result = subprocess.run(['forge', 'inspect', '--pretty', f'src/core/{contract_name}.sol:{contract_name}', 'storageLayout'], capture_output=True, text=True)
    with open(f'{contract_name}_current.md', 'w') as f:
        f.write(result.stdout)
    return parse_layout(f'{contract_name}_current.md')

if __name__ == "__main__":
    try:
        addresses = get_deployed_addresses()
        all_mismatches = {}

        for contract_name, address in addresses.items():
            print(f"Checking {contract_name}...")
            deployed_layout = get_storage_layout(contract_name, address)
            if deployed_layout is None:
                continue  # Skip if not deployed
            current_layout = get_current_layout(contract_name)
            mismatches = compare_layouts(deployed_layout, current_layout)
            if mismatches:
                all_mismatches[contract_name] = mismatches

        if all_mismatches:
            print("Mismatches found with deployed contracts:")
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
