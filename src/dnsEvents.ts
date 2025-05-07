import { ethers, Interface, Log, BytesLike } from "ethers";

// Optimism Node RPC URL
const OPTIMISM_RPC_URL = "https://mainnet.optimism.io";

// 3DNS Contract Address on Optimism
const DNS_CONTRACT_ADDRESS = "0xF97aAc6C8dbaEBCB54ff166d79706E3AF7a813c8";

// Event Signatures
const eventSignature1 =
  "event DNSRecordChanged(bytes32 indexed node, bytes name, uint16 resource, uint32 ttl, bytes record)";
const eventSignature2 =
  "event DNSRecordChanged(bytes32 indexed node, bytes name, uint16 resource, bytes record)";

// Create interfaces for each event signature
const iface1 = new Interface([eventSignature1]);
const iface2 = new Interface([eventSignature2]);

// Get topic hashes
const topicHash1 = iface1.getEvent("DNSRecordChanged")!.topicHash;
const topicHash2 = iface2.getEvent("DNSRecordChanged")!.topicHash;

/**
 * Decodes a domain name from DNS wire format.
 * Supports basic label sequences and termination by null label.
 * Does not support pointers/compression.
 */
function decodeDnsName(
  bytes: Uint8Array,
  offset: number
): { name: string; newOffset: number } {
  let name = "";
  let currentOffset = offset;
  while (currentOffset < bytes.length) {
    const length = bytes[currentOffset++];
    if (length === 0) break; // Null label, end of name
    if (currentOffset + length > bytes.length) {
      throw new Error("Buffer too short for DnsName label");
    }
    const label = Buffer.from(
      bytes.slice(currentOffset, currentOffset + length)
    ).toString("ascii");
    name += label + ".";
    currentOffset += length;
  }
  return { name, newOffset: currentOffset };
}

/**
 * Parses a concatenated list of DNS Resource Records from bytes.
 */
function parseDnsRrSet(recordHex: string, eventOwnerNameHex: BytesLike) {
  const records = [];
  const rawBytes = ethers.getBytes(recordHex);
  const ownerNameFromEvent = decodeDnsName(
    ethers.getBytes(eventOwnerNameHex),
    0
  ).name;
  let offset = 0;

  while (offset < rawBytes.length) {
    const rr: any = {};
    try {
      // 1. Owner Name
      const nameResult = decodeDnsName(rawBytes, offset);
      rr.name = nameResult.name;
      offset = nameResult.newOffset;
      if (rr.name !== ownerNameFromEvent) {
        console.warn(
          `  [WARN] RR name (${rr.name}) differs from event name (${ownerNameFromEvent})`
        );
      }

      // 2. Type (2 bytes)
      if (offset + 2 > rawBytes.length) break;
      rr.type = (rawBytes[offset] << 8) | rawBytes[offset + 1];
      offset += 2;

      // 3. Class (2 bytes)
      if (offset + 2 > rawBytes.length) break;
      rr.class = (rawBytes[offset] << 8) | rawBytes[offset + 1];
      offset += 2;

      // 4. TTL (4 bytes)
      if (offset + 4 > rawBytes.length) break;
      rr.ttl =
        (rawBytes[offset] << 24) |
        (rawBytes[offset + 1] << 16) |
        (rawBytes[offset + 2] << 8) |
        rawBytes[offset + 3];
      offset += 4;

      // 5. RDLength (2 bytes)
      if (offset + 2 > rawBytes.length) break;
      const rdLength = (rawBytes[offset] << 8) | rawBytes[offset + 1];
      offset += 2;

      // 6. RDATA
      if (offset + rdLength > rawBytes.length) break;
      const rdataBytes = rawBytes.slice(offset, offset + rdLength);
      offset += rdLength;

      if (rr.type === 2 && rr.class === 1) {
        // NS record
        rr.rdata = decodeDnsName(rdataBytes, 0).name;
      } else {
        rr.rdata = ethers.hexlify(rdataBytes);
      }
      records.push(rr);
    } catch (e: any) {
      console.error(
        "  Error parsing RR within RRSet:",
        e.message,
        "at offset",
        offset
      );
      break; // Stop parsing this RRSet if an error occurs
    }
  }
  return records;
}

async function main() {
  console.log("--- DNSRecordChanged Event Analyzer ---");
  console.log(
    "Topic Hash for Signature 1 (node, name, resource, ttl, record):",
    topicHash1
  );
  console.log(
    "Topic Hash for Signature 2 (node, name, resource, record):",
    topicHash2
  );
  console.log("\nConnecting to Optimism...");

  const provider = new ethers.JsonRpcProvider(OPTIMISM_RPC_URL);

  try {
    const network = await provider.getNetwork();
    console.log(
      `Connected to network: ${network.name} (chainId: ${network.chainId})`
    );
  } catch (error) {
    console.error("Failed to connect to Optimism:", error);
    return;
  }

  const fromBlock = 135286557;
  const toBlock = 135286557;

  console.log(`\nFetching events for contract: ${DNS_CONTRACT_ADDRESS}`);
  console.log(`Block range: ${fromBlock} to ${toBlock}\n`);

  // --- Fetch and process events for Signature 1 ---
  console.log(
    `Querying for events matching Signature 1 (topic: ${topicHash1})...`
  );
  try {
    const logs1 = await provider.getLogs({
      address: DNS_CONTRACT_ADDRESS,
      topics: [topicHash1],
      fromBlock,
      toBlock,
    });

    console.log(`Found ${logs1.length} raw log(s) for Signature 1.`);
    if (logs1.length > 0) {
      console.log(
        "\n--- Events for Signature 1 (node, name, resource, ttl, record) ---"
      );
      logs1.forEach((log: Log, index: number) => {
        try {
          const parsedLog = iface1.parseLog(
            log as { topics: ReadonlyArray<string>; data: string }
          );
          if (parsedLog && parsedLog.name === "DNSRecordChanged") {
            console.log(`Event ${index + 1}:`);
            console.log(`  Node: ${parsedLog.args.node}`);
            const eventNameStr = decodeDnsName(
              ethers.getBytes(parsedLog.args.name),
              0
            ).name;
            console.log(
              `  Name: ${eventNameStr} (bytes: ${parsedLog.args.name})`
            );
            console.log(`  Resource: ${parsedLog.args.resource}`);
            console.log(`  TTL: ${parsedLog.args.ttl}`);
            console.log(`  Raw Record (bytes): ${parsedLog.args.record}`);

            // Decode and print parsed RRs from the record field
            if (parsedLog.args.record && parsedLog.args.record !== "0x") {
              console.log("  Decoded RRs from Record field:");
              const rrs = parseDnsRrSet(
                parsedLog.args.record,
                parsedLog.args.name
              );
              rrs.forEach((rr, rrIndex) => {
                console.log(`    RR ${rrIndex + 1}:`);
                console.log(`      Owner: ${rr.name}`);
                console.log(`      Type: ${rr.type === 2 ? "NS" : rr.type}`);
                console.log(`      Class: ${rr.class === 1 ? "IN" : rr.class}`);
                console.log(`      TTL: ${rr.ttl}`);
                console.log(`      RDATA: ${rr.rdata}`);
              });
            }
            console.log(`  Block Number: ${log.blockNumber}`);
            console.log(`  Transaction Hash: ${log.transactionHash}`);
            console.log("  --------------------");
          }
        } catch (e) {
          console.error(
            `Error parsing log for Signature 1 (index ${index}):`,
            e,
            log
          );
        }
      });
    }
  } catch (error) {
    console.error("Error fetching events for Signature 1:", error);
  }

  // --- Fetch and process events for Signature 2 (basic printing) ---
  console.log(
    `\nQuerying for events matching Signature 2 (topic: ${topicHash2})...`
  );
  try {
    const logs2 = await provider.getLogs({
      address: DNS_CONTRACT_ADDRESS,
      topics: [topicHash2],
      fromBlock,
      toBlock,
    });

    console.log(`Found ${logs2.length} raw log(s) for Signature 2.`);
    if (logs2.length > 0) {
      console.log(
        "\n--- Events for Signature 2 (node, name, resource, record) ---"
      );
      logs2.forEach((log: Log, index: number) => {
        try {
          const parsedLog = iface2.parseLog(
            log as { topics: ReadonlyArray<string>; data: string }
          );
          if (parsedLog && parsedLog.name === "DNSRecordChanged") {
            console.log(`Event ${index + 1}:`);
            console.log(`  Node: ${parsedLog.args.node}`);
            const eventNameStr = decodeDnsName(
              ethers.getBytes(parsedLog.args.name),
              0
            ).name;
            console.log(
              `  Name: ${eventNameStr} (bytes: ${parsedLog.args.name})`
            );
            console.log(`  Resource: ${parsedLog.args.resource}`);
            console.log(`  Record (bytes): ${parsedLog.args.record}`);
            // Optionally decode for signature 2 as well if its record format is similar
            if (
              parsedLog.args.record &&
              parsedLog.args.record !== "0x" &&
              parsedLog.args.resource === 2
            ) {
              console.log(
                "  Decoded RRs from Record field (assuming NS record data format):"
              );
              // For sig2, 'record' is just RDATA for a single RR.
              // We'd need to know its type and class. Here, we assume it's NS and IN if resource is 2.
              // The `parseDnsRrSet` expects full RRs, so it's not directly usable unless we construct a fake RR.
              // For simplicity, if it's an NS record, let's try to parse RDATA directly.
              try {
                const rdataName = decodeDnsName(
                  ethers.getBytes(parsedLog.args.record),
                  0
                ).name;
                console.log(`    RDATA (decoded as NS name): ${rdataName}`);
              } catch (decodeError) {
                console.log(
                  "    Could not decode Record as a simple NS RDATA name."
                );
              }
            }
            console.log(`  Block Number: ${log.blockNumber}`);
            console.log(`  Transaction Hash: ${log.transactionHash}`);
            console.log("  --------------------");
          }
        } catch (e) {
          console.error(
            `Error parsing log for Signature 2 (index ${index}):`,
            e,
            log
          );
        }
      });
    }
  } catch (error) {
    console.error("Error fetching events for Signature 2:", error);
  }
}

main().catch((error) => {
  console.error("Error in main function:", error);
  process.exit(1);
});
