import { expect } from "chai";
import {
  Crs,
  newBarretenbergApiAsync,
  RawBuffer,
} from "@aztec/bb.js/dest/node/index.js";
import { executeCircuit, compressWitness } from "@noir-lang/acvm_js";
import circuit from "./circuits/ecdsa/target/ecdsa.json" assert { type: "json" };
import { decompressSync } from "fflate";
import { ECDSAPublickeyLEBytes } from "./index.js";
import { convertToHexAndPad } from "./utils/bits.js";
import {
  getECDSAPublicKeyLEFromPrivateKey,
  signECDSAChallenge,
} from "./utils/keys.js";

describe("Test claim logic", () => {
  let acirBuffer: any;
  let acirBufferUncompressed: any;
  let api: any;
  let acirComposer: any;

  let ecdsaPrivateKey: Buffer;
  let ecdsaPublicKey: ECDSAPublickeyLEBytes;

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

    ecdsaPrivateKey = Buffer.alloc(32, 8432);
    ecdsaPublicKey = getECDSAPublicKeyLEFromPrivateKey(ecdsaPrivateKey);
  });

  it("the valid witness should pass the circuit test", async () => {
    const witness = new Map<number, string>();
    const challenge = Buffer.alloc(32, 3741);
    const ecdsaSignature = signECDSAChallenge(ecdsaPrivateKey, challenge);
    const inputs = [
      ...ecdsaPublicKey.X,
      ...ecdsaPublicKey.Y,
      ...ecdsaSignature,
      ...challenge,
    ];

    inputs.forEach((input, index) => {
      witness.set(index + 1, convertToHexAndPad(input));
    });

    console.log(witness);

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
});
