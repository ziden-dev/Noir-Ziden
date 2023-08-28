import { expect } from "chai";
import {
  Crs,
  newBarretenbergApiAsync,
  RawBuffer,
} from "@aztec/bb.js/dest/node/index.js";
import { executeCircuit, compressWitness } from "@noir-lang/acvm_js";
import circuit from "./circuits/claim/target/claim.json" assert { type: "json" };
import { decompressSync } from "fflate";
import { CryptographyPrimitives } from "./crypto/index.js";
import { EDDSAPublicKey } from "./index.js";
import { convertToHexAndPad } from "./utils/bits.js";
import Claim from "./claim/claim.js";
import ClaimBuilder from "./claim/claim-builder.js";

describe("Test claim logic", () => {
  let acirBuffer: any;
  let acirBufferUncompressed: any;
  let api: any;
  let acirComposer: any;
  let claim: Claim;

  let schemaHash: BigInt;
  let expirationTime: BigInt;
  let sequel: BigInt;
  let slotValues: BigInt[];
  let subject: BigInt;

  let crypto: CryptographyPrimitives;
  let privateKey: Buffer;
  let publicKey: EDDSAPublicKey;

  before("setup variables", async () => {
    acirBuffer = Buffer.from(circuit.bytecode, "base64");
    acirBufferUncompressed = decompressSync(acirBuffer);
    api = await newBarretenbergApiAsync(4);
    const [_exact, circuitSize, _subgroup] = await api.acirGetCircuitSizes(
      acirBufferUncompressed
    );
    const subgroupSize = Math.pow(2, Math.ceil(Math.log2(circuitSize)));
    const crs = await Crs.new(subgroupSize + 1);
    await api.commonInitSlabAllocator(subgroupSize);
    await api.srsInitSrs(
      new RawBuffer(crs.getG1Data()),
      crs.numPoints,
      new RawBuffer(crs.getG2Data())
    );

    acirComposer = await api.acirNewAcirComposer(subgroupSize);

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

    crypto = await CryptographyPrimitives.getInstance();
    privateKey = Buffer.alloc(32, 8431);
    const pubkey = crypto.eddsa.prv2pub(privateKey);
    publicKey = {
      X: crypto.bn128ScalarField.toObject(pubkey[0]),
      Y: crypto.bn128ScalarField.toObject(pubkey[1]),
    };
  });

  it("the valid witness should pass the circuit test", async () => {
    /*
    claim: [Field; 8], 
    expected_schema: Field, 
    valid_until: Field, 
    expected_sequel: Field, 
    expected_subject: Field,
    public_key_x: Field,
    public_key_y: Field,
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field  
    */
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);
    const signature = await claim.eddsaSign(privateKey);
    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      publicKey.X,
      publicKey.Y,
      signature.s,
      signature.r8x,
      signature.r8y,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, convertToHexAndPad(input));
    });

    const witnessMap = await executeCircuit(acirBuffer, witness, () => {
      throw Error("unexpected oracle");
    });

    const witnessBuff = compressWitness(witnessMap);

    const proof = await api.acirCreateProof(
      acirComposer,
      acirBufferUncompressed,
      decompressSync(witnessBuff),
      false
    );

    await api.acirInitProvingKey(acirComposer, acirBufferUncompressed);
    const verified = await api.acirVerifyProof(acirComposer, proof, false);

    expect(verified).to.be.true;
  });

  it("the witness of an expired claim mustn't pass the circuit test", async () => {
    /*
    claim: [Field; 8], 
    expected_schema: Field, 
    valid_until: Field, 
    expected_sequel: Field, 
    expected_subject: Field,
    public_key_x: Field,
    public_key_y: Field,
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field  
    */
    const validUntil = BigInt(Date.now() + 80 * 60 * 1000);
    const signature = await claim.eddsaSign(privateKey);
    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      publicKey.X,
      publicKey.Y,
      signature.s,
      signature.r8x,
      signature.r8y,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, convertToHexAndPad(input));
    });

    const witnessMap = await executeCircuit(acirBuffer, witness, () => {
      throw Error("unexpected oracle");
    });

    const witnessBuff = compressWitness(witnessMap);

    const proof = await api.acirCreateProof(
      acirComposer,
      acirBufferUncompressed,
      decompressSync(witnessBuff),
      false
    );

    await api.acirInitProvingKey(acirComposer, acirBufferUncompressed);
    const verified = await api.acirVerifyProof(acirComposer, proof, false);

    expect(verified).to.be.false;
  });

  it("the witness with a wrong schema hash mustn't pass the circuit test", async () => {
    const wrongSchemaHash = BigInt("93819749189437913479");
    let wrongClaim = claim.clone();
    wrongClaim.schemaHash = wrongSchemaHash;
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);
    const signature = await claim.eddsaSign(privateKey);
    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      publicKey.X,
      publicKey.Y,
      signature.s,
      signature.r8x,
      signature.r8y,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, convertToHexAndPad(input));
    });

    let witnessMap;
    try {
      witnessMap = await executeCircuit(acirBuffer, witness, () => {
        throw Error("unexpected oracle");
      });
    } catch (err) {}

    expect(witnessMap).to.be.undefined;
  });

  it("the witness with a wrong subject mustn't pass the circuit test", async () => {
    const wrongSubject = subject.valueOf() + BigInt(11);
    let wrongClaim = claim.clone();
    wrongClaim.subject = wrongSubject;
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);
    const signature = await claim.eddsaSign(privateKey);
    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      publicKey.X,
      publicKey.Y,
      signature.s,
      signature.r8x,
      signature.r8y,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, convertToHexAndPad(input));
    });

    let witnessMap;
    try {
      witnessMap = await executeCircuit(acirBuffer, witness, () => {
        throw Error("unexpected oracle");
      });
    } catch (err) {}

    expect(witnessMap).to.be.undefined;
  });

  it("the witness with a wrong sequel mustn't pass the circuit test", async () => {
    const wrongSequel = sequel.valueOf() + BigInt(11);
    let wrongClaim = claim.clone();
    wrongClaim.subject = wrongSequel;
    const validUntil = BigInt(Date.now() + 30 * 60 * 1000);
    const signature = await claim.eddsaSign(privateKey);
    const witness = new Map<number, string>();

    const inputs = [
      ...claim.allSlots,
      schemaHash,
      validUntil,
      sequel,
      subject,
      publicKey.X,
      publicKey.Y,
      signature.s,
      signature.r8x,
      signature.r8y,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, convertToHexAndPad(input));
    });

    let witnessMap;
    try {
      witnessMap = await executeCircuit(acirBuffer, witness, () => {
        throw Error("unexpected oracle");
      });
    } catch (err) {}

    expect(witnessMap).to.be.undefined;
  });
});
