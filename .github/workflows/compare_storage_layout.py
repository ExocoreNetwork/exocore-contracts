#!/usr/bin/env python

import pandas as pd
import os

def parse_layout(file_path):
    expected_headers = ['Unnamed: 0', 'Name', 'Type', 'Slot', 'Offset', 'Bytes', 'Contract', 'Unnamed: 7']

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Error: File {file_path} does not exist.")

    # Read the file using pandas, with '|' as the delimiter
    df = pd.read_csv(file_path, delimiter='|', engine='python', header=0)

    # Trim leading/trailing whitespace from all columns
    df.columns = [col.strip() for col in df.columns]
    df = df.apply(lambda x: x.strip() if isinstance(x, str) else x)

    # Check headers
    if not all([df.columns[i] == expected_headers[i] for i in range(len(expected_headers))]):
        raise ValueError(f"Error: Headers in {file_path} do not match expected headers.")

    # Drop the second row (assuming it's a separator row)
    df = df.drop(df.index[1])

    # Combine relevant columns into a single string for comparison
    df['Combined'] = df[['Name', 'Type', 'Slot', 'Offset', 'Bytes']].apply(lambda row: '|'.join(row.values), axis=1)

    return df['Combined'].tolist()

def compare_layouts(clientChainGateway_entries, bootstrap_entries):
    mismatches = []
    length = len(bootstrap_entries)

    if length > len(clientChainGateway_entries):
        mismatches.append("Error: Bootstrap entries are more than ClientChainGateway entries.")
        return mismatches

    for i in range(length):
        if bootstrap_entries[i] != clientChainGateway_entries[i]:
            mismatches.append(f"Mismatch at position {i + 1}: {bootstrap_entries[i]} != {clientChainGateway_entries[i]}")

    return mismatches

if __name__ == "__main__":
    try:
        clientChainGateway_entries = parse_layout("ClientChainGateway.md")
        bootstrap_entries = parse_layout("Bootstrap.md")

        if not clientChainGateway_entries:
            raise ValueError("Error: No valid entries found in ClientChainGateway.md.")

        if not bootstrap_entries:
            raise ValueError("Error: No valid entries found in Bootstrap.md.")

        mismatches = compare_layouts(clientChainGateway_entries, bootstrap_entries)

        if mismatches:
            print(f"Mismatches found: {len(mismatches)}")
            for mismatch in mismatches:
                print(mismatch)
            exit(1)
        else:
            print("All entries in Bootstrap are present in ClientChainGateway at the correct positions.")
    except Exception as e:
        print(e)
        exit(1)

