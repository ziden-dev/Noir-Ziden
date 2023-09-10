import { expect } from "chai";
import {
  ECDSAPublickeyLEBytes,
  ECDSASignature,
  EDDSAPublicKey,
  EDDSASignature,
  Claim,
  ClaimBuilder,
  keyUtils,
  generateProofAndVerify,
  CircuitName,
  bitUtils,
} from "./index.js";

describe("Test claim logic", () => {
  let claim: Claim;
  let schemaHash: BigInt;
  let expirationTime: BigInt;
  let sequel: BigInt;
  let slotValues: BigInt[];
  let subject: BigInt;

  let eddsaPrivateKey: bigint;
  let eddsaPublicKey: EDDSAPublicKey;
  let ecdsaPrivateKey: bigint;
  let ecdsaPublicKey: ECDSAPublickeyLEBytes;
  let eddsaSignature: EDDSASignature;
  let ecdsaSignature: ECDSASignature;

  before("setup variables", async () => {
    schemaHash = BigInt("93819749189437913473");
    expirationTime = BigInt(Date.now() + 60 * 60 * 1000);
    sequel = BigInt(1);
    subject = BigInt("439798");
    slotValues = [
      BigInt("43818579187414812304"),
      BigInt("43818579187414812305"),
      BigInt("43818579187414812306"),
      BigInt("43818579187414812307"),
      BigInt("43818579187414812308"),
      BigInt("43818579187414812309"),
    ];
    claim = new ClaimBuilder()
      .withSchemaHash(schemaHash)
      .withExpirationTime(expirationTime)
      .withSequel(sequel)
      .withSubject(subject)
      .withSlotValue(2, slotValues[0])
      .withSlotValue(3, slotValues[1])
      .withSlotValue(4, slotValues[2])
      .withSlotValue(5, slotValues[3])
      .withSlotValue(6, slotValues[4])
      .withSlotValue(7, slotValues[5])
      .build();

    eddsaPrivateKey = BigInt("1235");
    const pubkey = await keyUtils.getEDDSAPublicKeyFromPrivateKey(
      eddsaPrivateKey
    );
    eddsaPublicKey = {
      X: pubkey.X,
      Y: pubkey.Y,
    };

    ecdsaPrivateKey = BigInt("123");
    ecdsaPublicKey =
      keyUtils.getECDSAPublicKeyLEFromPrivateKey(ecdsaPrivateKey);

    eddsaSignature = await claim.eddsaSign(eddsaPrivateKey);
    ecdsaSignature = await claim.ecdsaSign(ecdsaPrivateKey);
  });

  it("the valid witness should pass the circuit test", async () => {
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      eddsaPublicKey.X,
      eddsaPublicKey.Y,
      eddsaSignature.S,
      eddsaSignature.R8X,
      eddsaSignature.R8Y,
      ...ecdsaPublicKey.X,
      ...ecdsaPublicKey.Y,
      ...ecdsaSignature,
      2,
      claim.getSlotValue(2).valueOf() + BigInt(1),
      1,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, bitUtils.convertToHexAndPad(input));
    });

    const verified = await generateProofAndVerify(witness, CircuitName.CLAIM);
    expect(verified).to.be.true;
  });

  it("the witness of an expired claim mustn't pass the circuit test", async () => {
    const validUntil = BigInt(Date.now() + 80 * 60 * 1000);

    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      eddsaPublicKey.X,
      eddsaPublicKey.Y,
      eddsaSignature.S,
      eddsaSignature.R8X,
      eddsaSignature.R8Y,
      ...ecdsaPublicKey.X,
      ...ecdsaPublicKey.Y,
      ...ecdsaSignature,
      2,
      claim.getSlotValue(2).valueOf() + BigInt(1),
      1,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, bitUtils.convertToHexAndPad(input));
    });

    const verified = await generateProofAndVerify(witness, CircuitName.CLAIM);
    expect(verified).to.be.true;
  });
  it("the witness that unfulfilles the query mustn't pass the circuit test", async () => {
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      eddsaPublicKey.X,
      eddsaPublicKey.Y,
      eddsaSignature.S,
      eddsaSignature.R8X,
      eddsaSignature.R8Y,
      ...ecdsaPublicKey.X,
      ...ecdsaPublicKey.Y,
      ...ecdsaSignature,
      2,
      claim.getSlotValue(4),
      0,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, bitUtils.convertToHexAndPad(input));
    });

    const verified = await generateProofAndVerify(witness, CircuitName.CLAIM);
    expect(verified).to.be.false;
  });
  it("the witness with a wrong schema hash mustn't pass the circuit test", async () => {
    const wrongSchemaHash = BigInt("93819749189437913479");
    let wrongClaim = claim.clone();
    wrongClaim.schemaHash = wrongSchemaHash;
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      eddsaPublicKey.X,
      eddsaPublicKey.Y,
      eddsaSignature.S,
      eddsaSignature.R8X,
      eddsaSignature.R8Y,
      ...ecdsaPublicKey.X,
      ...ecdsaPublicKey.Y,
      ...ecdsaSignature,
      2,
      claim.getSlotValue(2).valueOf() + BigInt(1),
      1,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, bitUtils.convertToHexAndPad(input));
    });

    const verified = await generateProofAndVerify(witness, CircuitName.CLAIM);
    expect(verified).to.be.false;
  });

  it("the witness with a wrong subject mustn't pass the circuit test", async () => {
    const wrongSubject = subject.valueOf() + BigInt(11);
    let wrongClaim = claim.clone();
    wrongClaim.subject = wrongSubject;
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      eddsaPublicKey.X,
      eddsaPublicKey.Y,
      eddsaSignature.S,
      eddsaSignature.R8X,
      eddsaSignature.R8Y,
      ...ecdsaPublicKey.X,
      ...ecdsaPublicKey.Y,
      ...ecdsaSignature,
      2,
      claim.getSlotValue(2).valueOf() + BigInt(1),
      1,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, bitUtils.convertToHexAndPad(input));
    });

    const verified = await generateProofAndVerify(witness, CircuitName.CLAIM);
    expect(verified).to.be.false;
  });

  it("the witness with a wrong sequel mustn't pass the circuit test", async () => {
    const wrongSequel = sequel.valueOf() + BigInt(11);
    let wrongClaim = claim.clone();
    wrongClaim.subject = wrongSequel;
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      eddsaPublicKey.X,
      eddsaPublicKey.Y,
      eddsaSignature.S,
      eddsaSignature.R8X,
      eddsaSignature.R8Y,
      ...ecdsaPublicKey.X,
      ...ecdsaPublicKey.Y,
      ...ecdsaSignature,
      2,
      claim.getSlotValue(2).valueOf() + BigInt(1),
      1,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, bitUtils.convertToHexAndPad(input));
    });

    const verified = await generateProofAndVerify(witness, CircuitName.CLAIM);
    expect(verified).to.be.false;
  });
});
