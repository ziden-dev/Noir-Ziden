import claimCircuit from "../circuits-abi/claim.json" assert { type: "json" };
import imtCircuit from "../circuits-abi/indexed_merkle_tree.json" assert { type: "json" };
import stateCircuit from "../circuits-abi/state.json" assert { type: "json" };
import eddsaClaimPresentationCircuit from "../circuits-abi/eddsa_claim_presentation.json" assert { type: "json" };
import ecdsaClaimPresentationCircuit from "../circuits-abi/ecdsa_claim_presentation.json" assert { type: "json" };
import { decompressSync } from "fflate";
import { CircuitName, Proof } from "../index.js";
import {
  Crs,
  RawBuffer,
  newBarretenbergApiAsync,
} from "@aztec/bb.js/dest/node/index.js";
import { compressWitness, executeCircuit } from "@noir-lang/acvm_js";

export function getCircuitABIFromName(circuitName: CircuitName): any {
  switch (circuitName) {
    case CircuitName.CLAIM:
      return claimCircuit;
    case CircuitName.INDEXED_MERKLE_TREE:
      return imtCircuit;
    case CircuitName.STATE:
      return stateCircuit;
    case CircuitName.EDDSA_CLAIM_PRESENTATION:
      return eddsaClaimPresentationCircuit;
    case CircuitName.ECDSA_CLAIM_PRESENTATION:
      return ecdsaClaimPresentationCircuit;
  }
}
export async function generateProofAndVerify(
  witness: Map<number, string>,
  circuitName: CircuitName
) {
  try {
    let circuitABI = getCircuitABIFromName(circuitName);
    let acirBuffer = Buffer.from(circuitABI.bytecode, "base64");
    let acirBufferUncompressed = decompressSync(acirBuffer);
    let api = await newBarretenbergApiAsync(4);
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

    let acirComposer = await api.acirNewAcirComposer(subgroupSize);

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
    return verified;
  } catch (_err) {
    return false;
  }
}

export async function generateProof(
  witness: Map<number, string>,
  circuitName: CircuitName
): Promise<Proof> {

  let circuitABI = getCircuitABIFromName(circuitName);
  let acirBuffer = Buffer.from(circuitABI.bytecode, "base64");
  let acirBufferUncompressed = decompressSync(acirBuffer);
  let api = await newBarretenbergApiAsync(4);
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

  let acirComposer = await api.acirNewAcirComposer(subgroupSize);

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

  var numberPublicInputs = 0;
  for (var field of circuitABI.abi.parameters) {
    if (field.visibility == "public") numberPublicInputs = numberPublicInputs + 1;
  }

  return {
    slicedProof: proof.slice(32 * numberPublicInputs),
    publicInputs: getPublicInputs(proof, numberPublicInputs)
  };

}

function getPublicInputs(proof: any, len: number) {
  var res = [];
  for (var i = 0; i < len; i++) {
    res.push(proof.slice(i * 32, (i + 1) * 32));
  }
  return res;
}


