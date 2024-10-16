#!/usr/bin/env python

import pandas as pd
import subprocess

def parse_output(contract_name, lines):
    # Clean up the output and create a dataframe
    data = []
    separator_line = len(lines);
    for i, line in enumerate(lines):  # start from the line next to the separator
        if i > separator_line and line.startswith('|'):
            parts = [part.strip() for part in line.split('|')[1:-1]]  # Remove empty first and last elements
            data.append(parts[:6])  # Keep Name, Type, Slot, Offset, Bytes, Contract
        elif line.startswith('|') and 'Name' in line:
            separator_line = i + 1
    
    if not data:
        raise Exception(f"No valid storage layout data found for {contract_name}")

    df = pd.DataFrame(data, columns=['Name', 'Type', 'Slot', 'Offset', 'Bytes', 'Contract'])
    
    # Convert numeric columns
    for col in ['Slot', 'Offset', 'Bytes']:
        df[col] = pd.to_numeric(df[col])

    return df

def get_current_layout(contract_name):
    result = subprocess.run(['forge', 'inspect', f'src/core/{contract_name}.sol:{contract_name}', 'storage-layout', '--pretty'], capture_output=True, text=True)
    print(f"finished executing forge inspect for {contract_name}")

    if result.returncode != 0:
        raise Exception(f"Error getting current layout for {contract_name}: {result.stderr}")

    return parse_output(contract_name, result.stdout.split('\n'))
    
def compare_layouts(old_layout, new_layout):
    mismatches = []

    # Ensure both dataframes have the same columns
    columns = ['Name', 'Type', 'Slot', 'Offset', 'Bytes']
    old_layout = old_layout[columns].copy()
    new_layout = new_layout[columns].copy()

    # Compare non-gap variables
    for index, row in old_layout.iterrows():
        if row['Name'] != '__gap':
            current_row = new_layout.loc[new_layout['Name'] == row['Name']]
            if current_row.empty:
                mismatches.append(f"Variable {row['Name']} is missing in the current layout")
            elif not current_row.iloc[0].equals(row):
                mismatches.append(f"Variable {row['Name']} has changed")
    
    if not mismatches:
        print(f"No mismatches found")

    return mismatches

if __name__ == "__main__":
    try:
        clientChainGateway_layout = get_current_layout("ClientChainGateway")
        bootstrap_layout = get_current_layout("Bootstrap")

        if clientChainGateway_layout.empty:
            raise ValueError("Error: No valid entries found for ClientChainGateway.")

        if bootstrap_layout.empty:
            raise ValueError("Error: No valid entries found for Bootstrap.")

        mismatches = compare_layouts(bootstrap_layout, clientChainGateway_layout)

        if mismatches:
            print(f"Mismatches found: {len(mismatches)}")
            for mismatch in mismatches:
                print(mismatch)
            exit(1)
        else:
            print("All entries in Bootstrap match ClientChainGateway at the correct positions.")
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
