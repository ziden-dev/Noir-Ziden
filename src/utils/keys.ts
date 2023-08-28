import buildEddsa from "../crypto/eddsa.js";
import { getCurveFromName } from "../crypto/ffjavascript.js";
import { Entity } from "../state/state.js";
import pkg from "secp256k1";
const { ecdsaSign, publicKeyCreate } = pkg;
import {
  bigInt2Buffer,
  buffer2BigInt,
  uint8ArrayToBigInt,
} from "../crypto/wasmcurves/utils.js";
import { ECDSAPublicKey, ECDSAPublickeyLEBytes } from "src/index.js";
import { numToBytesLE } from "./bits.js";

export async function getEDDSAPublicKeyFromPrivateKey(privateKey: bigint) {
  const bn128 = await getCurveFromName("bn128", true);
  const F = bn128.Fr;
  var eddsa = await buildEddsa(F);

  const pubkey = eddsa.prv2pub(bigInt2Buffer(privateKey));
  return {
    X: F.toObject(pubkey[0]),
    Y: F.toObject(pubkey[1]),
  };
}



export async function signEDDSAChallenge(
  privateKey: bigint,
  challenge: bigint
) {
  const bn128 = await getCurveFromName("bn128", true);
  const F = bn128.Fr;
  var eddsa = await buildEddsa(F);
  const message = F.e(challenge);
  const signature = eddsa.signPoseidon(bigInt2Buffer(privateKey), message);
  return {
    signature_s: signature.S,
    signature_r8_x: F.toObject(signature.R8[0]),
    signature_r8_y: F.toObject(signature.R8[1]),
  };
}

export async function idOwnershipByEDDSASignature(
  privateKey: bigint,
  entity: Entity,
  challenge: bigint
) {
  const pubkey = await getEDDSAPublicKeyFromPrivateKey(privateKey);
  const signature = await signEDDSAChallenge(privateKey, challenge);
  return {
    ...entity.getAuthProof(pubkey.X),
    ...signature,
    challenge,
  };
}

export function getECDSAPublicKeyFromPrivateKey(
  privateKey: Buffer
): ECDSAPublicKey {
  const pubKey = publicKeyCreate(privateKey, false);
  const pubKeyX = pubKey.slice(1, 33);
  const pubKeyY = pubKey.slice(33, 65);
  return {
    X: uint8ArrayToBigInt(pubKeyX),
    Y: uint8ArrayToBigInt(pubKeyY),
  };
}

export function getECDSAPublicKeyLEFromPrivateKey(
  privateKey: Buffer
): ECDSAPublickeyLEBytes {
  const pubKey = publicKeyCreate(privateKey, false);
  const pubKeyX = pubKey.slice(1, 33);
  const pubKeyY = pubKey.slice(33, 65);
  return {
    X: numToBytesLE(uint8ArrayToBigInt(pubKeyX)),
    Y: numToBytesLE(uint8ArrayToBigInt(pubKeyY)),
  };
}

export function signECDSAChallenge(
  privateKey: Buffer,
  challenge: Buffer
) {
  const res = ecdsaSign(challenge, privateKey);
  return Array.from(res.signature);
}

export async function idOwnershipByECDSASignature(
  privateKey: Buffer,
  entity: Entity,
  challenge: Buffer
) {
  const pubkey = getECDSAPublicKeyFromPrivateKey(privateKey);
  const signature = await signECDSAChallenge(privateKey, challenge);
  return {
    ...entity.getAuthProof(pubkey.X.valueOf()),
    signature,
    challenge: buffer2BigInt(challenge),
  };
}
