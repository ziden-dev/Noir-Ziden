import buildEddsa from "../crypto/eddsa.js";
import { getCurveFromName } from "../crypto/ffjavascript.js";
import { Entity, Issuer } from "../state/state.js";
import pkg from "secp256k1";
const { ecdsaSign, publicKeyCreate } = pkg;
import {
  bigInt2Uint8Array,
  uint8ArrayToBigInt,
} from "../crypto/wasmcurves/utils.js";
import { ECDSAPublickeyLEBytes } from "../index.js";
import { numToBytesLE } from "./bits.js";
import { AddAuthOperation, IssueClaimOperation, RevokeAuthOperation, RevokeClaimOperation, StateTransitionOperation } from "./type.js";

export async function getEDDSAPublicKeyFromPrivateKey(privateKey: bigint) {
  const bn128 = await getCurveFromName("bn128", true);
  const F = bn128.Fr;
  var eddsa = await buildEddsa(F);

  const pubkey = eddsa.prv2pub(bigInt2Uint8Array(privateKey, 32));
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
  const signature = eddsa.signPoseidon(bigInt2Uint8Array(privateKey, 32), message);
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
export async function getECDSAPublicKeyFromPrivateKey(privateKey: bigint) {
  const pubKey = publicKeyCreate(bigInt2Uint8Array(privateKey, 32), false);
  const pubKeyX = pubKey.slice(1, 33);
  const pubKeyY = pubKey.slice(33, 65);
  return {
    X: uint8ArrayToBigInt(pubKeyX),
    Y: uint8ArrayToBigInt(pubKeyY)
  }
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

export async function signECDSAChallenge(privateKey: bigint, challenge: bigint) {
  const res = ecdsaSign(bigInt2Uint8Array(challenge, 32), bigInt2Uint8Array(privateKey, 32));
  return Array.from(res.signature);
}

export async function idOwnershipByECDSASignature(privateKey: bigint, entity: Entity, challenge: bigint) {
  const pubkey = await getECDSAPublicKeyFromPrivateKey(privateKey);
  const signature = await signECDSAChallenge(privateKey, challenge);
  return {
    ...entity.getAuthProof(pubkey.X),
    signature,
    challenge
  }
}


function doOperations(entity: Entity, operations: StateTransitionOperation[]) {
  for (var operation of operations) {
    switch (operation.type) {
      case "issueClaimOperation":
        const issueClaimOperation = operation as IssueClaimOperation;
        if (entity instanceof Issuer) {
          entity.addClaim(issueClaimOperation.slot);
        }
        break;
      case "revokeClaimOperation":
        const revokeClaimOperation = operation as RevokeClaimOperation;
        if (entity instanceof Issuer) {
          entity.revokeAuth(revokeClaimOperation.claimHash);
        }
        break;
      case "addAuthOperation":
        const addAuthOperation = operation as AddAuthOperation;
        entity.addAuth(addAuthOperation.publicKeyX, addAuthOperation.publicKeyY);
        break;
      case "revokeAuthOperation":
        const revokeAuthOperation = operation as RevokeAuthOperation;
        entity.revokeAuth(revokeAuthOperation.publicKeyX);
        break;
    }
  }
}


export async function stateTransitionByEDDSASignature(privateKey: bigint, entity: Entity, operations: StateTransitionOperation[]) {
  const pubkey = await getEDDSAPublicKeyFromPrivateKey(privateKey);
  const authProof = entity.getAuthProof(pubkey.X);
  authProof.old_state = authProof.state;
  doOperations(entity, operations);
  const new_state = entity.state();
  const challenge = entity.authTree.hash([authProof.old_state, new_state]);
  const signature = await signEDDSAChallenge(privateKey, challenge);
  return {
    ...authProof,
    new_state,
    ...signature
  }
}

export async function stateTransitionByECDSASignature(privateKey: bigint, entity: Entity, operations: StateTransitionOperation[]) {
  const pubkey = await getECDSAPublicKeyFromPrivateKey(privateKey);
  const authProof = entity.getAuthProof(pubkey.X);
  authProof.old_state = authProof.state;
  doOperations(entity, operations);
  const new_state = entity.state();
  const challenge = entity.authTree.hash([authProof.old_state, new_state]);
  const signature = await signECDSAChallenge(privateKey, challenge);
  return {
    ...authProof,
    new_state,
    signature
  }
}


