import { Entity, Issuer } from "../state/state.js";
import pkg from "secp256k1";
const { ecdsaSign, publicKeyCreate } = pkg;
import { bigInt2Uint8Array, uint8ArrayToBigInt } from "../utils/bits.js";
import {
  ClaimExistenceProofWitness,
  ClaimNonRevocationProofWitness,
  ECDSAPublickeyLEBytes,
  ECDSASignature,
  EDDSAPublicKey,
  EDDSASignature,
  IdOwnershipByECDSASignatureWitness,
  IdOwnershipByEDDSASignatureWitness,
  MembershipSetProofWitness,
  NonMembershipSetProofWitness,
  StateTransitionByECDSASignatureWitness,
  StateTransitionByEDDSASignatureWitness,
  AddAuthOperation,
  IssueClaimOperation,
  RevokeAuthOperation,
  RevokeClaimOperation,
  StateTransitionOperation,
} from "../index.js";
import { CryptographyPrimitives } from "../crypto/index.js";
import { bigInt2BytesLE } from "./bits.js";

import { ECDSAPublicKey } from "../index.js";
import { NormalMerkleTree } from "../tree/normal-merkle-tree.js";
import { IndexedMerkleTree } from "../tree/indexed-merkle-tree.js";

export async function getEDDSAPublicKeyFromPrivateKey(
  privateKey: BigInt
): Promise<EDDSAPublicKey> {
  const crypto = await CryptographyPrimitives.getInstance();
  const F = crypto.bn128ScalarField;
  var eddsa = crypto.eddsa;

  const pubkey = eddsa.prv2pub(bigInt2Uint8Array(privateKey, 32));
  return {
    X: F.toObject(pubkey[0]),
    Y: F.toObject(pubkey[1]),
  };
}

export async function signEDDSAChallenge(
  privateKey: BigInt,
  challenge: BigInt
): Promise<EDDSASignature> {
  const crypto = await CryptographyPrimitives.getInstance();
  const F = crypto.bn128ScalarField;
  var eddsa = crypto.eddsa;
  const message = F.e(challenge);
  const signature = eddsa.signPoseidon(
    bigInt2Uint8Array(privateKey, 32),
    message
  );
  return {
    S: signature.S,
    R8X: F.toObject(signature.R8[0]),
    R8Y: F.toObject(signature.R8[1]),
  };
}

export async function idOwnershipByEDDSASignature(
  privateKey: BigInt,
  entity: Entity,
  challenge: BigInt
): Promise<IdOwnershipByEDDSASignatureWitness> {
  const pubkey = await getEDDSAPublicKeyFromPrivateKey(privateKey);
  const signature = await signEDDSAChallenge(privateKey, challenge);
  return {
    ...entity.getAuthProof(pubkey.X),
    ...signature,
    challenge,
  };
}
export function getECDSAPublicKeyFromPrivateKey(
  privateKey: BigInt
): ECDSAPublicKey {
  const pubKey = publicKeyCreate(bigInt2Uint8Array(privateKey, 32), false);
  const pubKeyX = pubKey.slice(1, 33);
  const pubKeyY = pubKey.slice(33, 65);
  return {
    X: uint8ArrayToBigInt(pubKeyX),
    Y: uint8ArrayToBigInt(pubKeyY),
  };
}
export function getECDSAPublicKeyLEFromPrivateKey(
  privateKey: BigInt
): ECDSAPublickeyLEBytes {
  const pubKey = publicKeyCreate(bigInt2Uint8Array(privateKey, 32), false);
  const pubKeyX = pubKey.slice(1, 33);
  const pubKeyY = pubKey.slice(33, 65);
  return {
    X: pubKeyX,
    Y: pubKeyY,
  };
}

export async function signECDSAChallenge(
  privateKey: BigInt,
  challenge: BigInt
): Promise<ECDSASignature> {
  const res = ecdsaSign(
    bigInt2Uint8Array(challenge, 32),
    bigInt2Uint8Array(privateKey, 32)
  );
  return Array.from(res.signature);
}

export async function idOwnershipByECDSASignature(
  privateKey: BigInt,
  entity: Entity,
  challenge: BigInt
): Promise<IdOwnershipByECDSASignatureWitness> {
  const pubkey = getECDSAPublicKeyFromPrivateKey(privateKey);
  const signature = await signECDSAChallenge(privateKey, challenge);
  const authProof = entity.getAuthProof(pubkey.X);
  return {
    ...authProof,
    publicKeyX: bigInt2BytesLE(authProof.publicKeyX, 32),
    publicKeyY: bigInt2BytesLE(authProof.publicKeyY, 32),
    signature,
    challenge,
  };
}

function doOperations(entity: Entity, operations: StateTransitionOperation[]) {
  for (var operation of operations) {
    switch (operation.type) {
      case "issueClaim":
        const issueClaimOperation = operation as IssueClaimOperation;
        if (entity instanceof Issuer) {
          entity.addClaim(issueClaimOperation.claim);
        }
        break;
      case "revokeClaim":
        const revokeClaimOperation = operation as RevokeClaimOperation;
        if (entity instanceof Issuer) {
          entity.revokeClaim(revokeClaimOperation.claimHash);
        }
        break;
      case "addAuth":
        const addAuthOperation = operation as AddAuthOperation;
        entity.addAuth(
          addAuthOperation.publicKeyX,
          addAuthOperation.publicKeyY,
          addAuthOperation.publicKeyType
        );
        break;
      case "revokeAuth":
        const revokeAuthOperation = operation as RevokeAuthOperation;
        entity.revokeAuth(revokeAuthOperation.publicKeyX);
        break;
    }
  }
}

export async function stateTransitionByEDDSASignature(
  privateKey: BigInt,
  entity: Entity,
  operations: StateTransitionOperation[]
): Promise<StateTransitionByEDDSASignatureWitness> {
  const pubkey = await getEDDSAPublicKeyFromPrivateKey(privateKey);
  const authProof = entity.getAuthProof(pubkey.X);
  authProof.oldState = authProof.state;
  delete authProof.state;
  doOperations(entity, operations);
  const newState = entity.state();
  const challenge = entity.authTree.hash([authProof.oldState, newState]);
  const signature = await signEDDSAChallenge(privateKey, challenge);
  return {
    ...authProof,
    newState,
    ...signature,
  };
}

export async function stateTransitionByECDSASignature(
  privateKey: BigInt,
  entity: Entity,
  operations: StateTransitionOperation[]
): Promise<StateTransitionByECDSASignatureWitness> {
  const pubkey = getECDSAPublicKeyFromPrivateKey(privateKey);
  const authProof = entity.getAuthProof(pubkey.X);
  authProof.old_state = authProof.state;
  delete authProof.state;
  doOperations(entity, operations);
  const new_state = entity.state();
  const challenge = entity.authTree.hash([authProof.old_state, new_state]);
  const signature = await signECDSAChallenge(privateKey, challenge);
  return {
    ...authProof,
    publicKeyX: bigInt2BytesLE(authProof.publicKeyX, 32),
    publicKeyY: bigInt2BytesLE(authProof.publicKeyY, 32),
    new_state,
    signature,
  };
}

export async function ClaimExistenceProof(
  issuer: Issuer,
  claimHash: BigInt
): Promise<ClaimExistenceProofWitness> {
  var claimIndex = issuer.claimTree.getIndex(claimHash);
  var proof = issuer.claimTree.getPathProof(claimIndex);
  var claimRoot = issuer.claimTree.getRoot();
  var authRoot = issuer.authTree.getRoot();
  var revokedClaimRoot = issuer.revokedClaimTree.getRoot();
  var issuerState = issuer.state();
  return {
    claimPath: proof.path,
    claimIndex: proof.index,
    claimRoot,
    authRoot,
    revokedClaimRoot,
    issuerState,
  };
}

export async function ClaimNonRevocationProof(
  issuer: Issuer,
  claimHash: BigInt
): Promise<ClaimNonRevocationProofWitness> {
  var proof = issuer.revokedClaimTree.getPathProofLow(claimHash);
  var claimRoot = issuer.claimTree.getRoot();
  var authRoot = issuer.authTree.getRoot();
  var revokedClaimRoot = issuer.revokedClaimTree.getRoot();
  var issuerState = issuer.state();
  return {
    pathLow: proof.pathLow,
    valLow: proof.leafLow.val,
    nextVal: proof.leafLow.nextVal,
    nextIdx: proof.leafLow.nextIdx,
    indexLow: proof.idxLow,
    revokedClaimRoot,
    authRoot,
    claimRoot,
    issuerState,
  };
}

export async function MembershipSetProof(
  n: number,
  hashser: any,
  values: BigInt[],
  setIndex: number
): Promise<MembershipSetProofWitness> {
  var merkleTree = new NormalMerkleTree(n, hashser);
  for (var value of values) {
    merkleTree.insert(value);
  }
  var setPath = merkleTree.getPathProof(setIndex).path;
  var setRoot = merkleTree.getRoot();
  return {
    setRoot,
    setIndex,
    setPath,
  };
}

export async function NonMembershipSetProof(
  n: number,
  hashser: any,
  values: BigInt[],
  val: BigInt
): Promise<NonMembershipSetProofWitness> {
  var nmpMerkleTree = new IndexedMerkleTree(n, hashser);
  for (var value of values) {
    nmpMerkleTree.insert(value);
  }
  var res = nmpMerkleTree.getPathProofLow(val);
  var nmpPathLow = res.pathLow;
  var nmpIndexLow = res.idxLow;
  var nmpValLow = res.leafLow.val;
  var nmpNextVal = res.leafLow.nextVal;
  var nmpNextIndex = res.leafLow.nextIdx;

  var nmpRoot = nmpMerkleTree.getRoot();

  return {
    nmpPathLow,
    nmpValLow,
    nmpNextVal,
    nmpNextIndex,
    nmpIndexLow,
    nmpRoot,
  };
}
