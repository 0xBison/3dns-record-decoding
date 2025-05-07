import dnsPacketDefault, { Answer, OptAnswer } from "dns-packet";
import { Buffer } from "buffer";

// Cast the default import to 'any' to bypass potential type issues with sub-namespaces
const dnsPacket: any = dnsPacketDefault;

// Define a type for standard records by excluding OptAnswer from Answer
type StandardRecord = Exclude<Answer, OptAnswer>;

// recordHexData can be changed to test different RR sets.
// Example 1: Two NS records (moe.box)
const recordHexData =
  "036d6f6503626f78000002000100003840001905646572656b026e730a636c6f7564666c61726503636f6d00036d6f6503626f78000002000100003840001a06646170686e65026e730a636c6f7564666c61726503636f6d00";

// Example 2: Single A record (bookings.ohms.box)
// const recordHexData =
//   "08626f6f6b696e6773046f686d7303626f78000001000100000e100004ac420046";

// Helper type guard to check if a record is a standard (non-OPT) record
function isStandardRecord(record: Answer): record is StandardRecord {
  return record.type !== "OPT";
}

async function main() {
  console.log(
    "--- Testing dns-packet library with iterative RRSet parsing ---"
  );
  console.log("Attempting to parse this RRSet hex data:", recordHexData);

  try {
    const recordsBuffer = Buffer.from(
      recordHexData.startsWith("0x")
        ? recordHexData.substring(2)
        : recordHexData,
      "hex"
    );
    let offset = 0;
    const decodedRecords: Answer[] = [];

    while (offset < recordsBuffer.length) {
      const rr = dnsPacket.answer.decode(recordsBuffer, offset);
      if (!rr) {
        console.error(
          "dnsPacket.answer.decode returned null or undefined. Stopping."
        );
        break;
      }
      decodedRecords.push(rr);
      const consumedLength = dnsPacket.answer.encodingLength(rr);
      if (consumedLength === 0) {
        console.error(
          "Consumed length is 0, stopping to prevent infinite loop. RR:",
          JSON.stringify(rr)
        );
        break;
      }
      offset += consumedLength;
    }

    console.log(
      `\nSuccessfully decoded ${decodedRecords.length} record(s) iteratively.`
    );

    if (decodedRecords.length > 0) {
      console.log("\nDecoded Resource Records:");
      decodedRecords.forEach((rr: Answer, index: number) => {
        console.log(`\n  RR ${index + 1}:`);
        console.log(`    Name: ${rr.name}`);
        console.log(`    Type: ${rr.type}`);

        if (isStandardRecord(rr)) {
          console.log(`    Class: ${rr.class}`);
          console.log(`    TTL: ${rr.ttl}`);

          if (rr.type === "NS") {
            console.log(`    RDATA (Nameserver): ${rr.data}`);
          } else if (rr.type === "A" || rr.type === "AAAA") {
            console.log(`    RDATA (IP Address): ${rr.data}`);
          } else if (rr.data) {
            if (typeof rr.data === "string") {
              console.log(`    RDATA: ${rr.data}`);
            } else if (Buffer.isBuffer(rr.data)) {
              console.log(`    RDATA (Buffer): ${rr.data.toString("hex")}`);
            } else if (typeof rr.data === "object") {
              console.log(
                `    RDATA (Object/Other): ${JSON.stringify(rr.data)}`
              );
            } else {
              console.log(`    RDATA: ${rr.data}`);
            }
          } else {
            console.log(`    RDATA: missing or null`);
          }
        } else {
          const optRecord = rr as OptAnswer;
          console.log("    (EDNS OPT Record)");
          console.log(`    UDP Payload Size: ${optRecord.udpPayloadSize}`);
          console.log(`    Flags: ${optRecord.flags}`);
          if (optRecord.options && optRecord.options.length > 0) {
            console.log(`    Options: ${JSON.stringify(optRecord.options)}`);
          }
        }
        console.log("    ----");
      });
    } else {
      console.log("No records found in the provided hex data.");
    }
  } catch (error: any) {
    console.error(
      "\nError parsing DNS records with dns-packet:",
      error.message
    );
    // console.error("Full error object:", error);
    console.error("Input hex data was:", recordHexData);
  }
}

main().catch((err) => {
  console.error("Error in main function:", err);
});
