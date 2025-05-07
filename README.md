# 3DNS Record Decoding

This project contains TypeScript scripts designed to interact with the 3DNS protocol on optimism.

## Overview

The primary scripts are:
1.  **3DNS DNSRecordChanged Event Listener**: Fetches historical `DNSRecordChanged` events from a 3DNS contract on Optimism using two different event signatures and decodes the event data.
2.  **DNS Packet Library Test**: A utility script to demonstrate parsing of DNS wire-format resource records using the `dns-packet` library.

## Setup

1.  Clone the repository (if applicable).
2.  Install dependencies:
    ```bash
    npm install
    ```

## Scripts

To run any of these scripts, first ensure dependencies are installed. The scripts will compile the TypeScript code and then execute the JavaScript output.

### 1. 3DNS DNSRecordChanged Event Listener

*   **Command**: `npm run dns-events`
*   **File**: `src/dnsEvents.ts`
*   **Description**: This script is set up to find `DNSRecordChanged` events from the specified 3DNS contract address on Optimism. It checks for two potential event signatures.
    *   It currently uses a basic custom decoder for DNS names found in the event arguments.
    *   The output includes the raw event data and any decoded information.

### 2. DNS Packet Library Test

*   **Command**: `npm run test-dns-packet`
*   **File**: `src/testDnsPacketLib.ts`
*   **Description**: This script demonstrates how to use the `dns-packet` library to iteratively parse a sequence of DNS resource records provided in hexadecimal wire format. It's useful for testing and understanding DNS record parsing.

## Configuration

*   **RPC URL**: The scripts currently use a public Optimism RPC URL (`https://mainnet.optimism.io`). For more robust or production use, consider replacing this with a dedicated RPC provider URL in the respective `.ts` files.
*   **Contract Addresses & Block Ranges**: These are hardcoded in the script and can be modified as needed for different contracts or query periods. 