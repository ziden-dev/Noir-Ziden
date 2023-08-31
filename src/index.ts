import Claim from "./claim/claim.js";

export interface EDDSAPublicKey {
  X: BigInt;
  Y: BigInt;
}

export interface ECDSAPublicKey {
  X: BigInt;
  Y: BigInt;
}

export interface ECDSAPublickeyLEBytes {
  X: Uint8Array;
  Y: Uint8Array;
}

export interface EDDSASignature {
  R8X: BigInt;
  R8Y: BigInt;
  S: BigInt;
}

export interface IdOwnershipByEDDSASignatureWitness {
  publicKeyX: BigInt,
  publicKeyY: BigInt,
  authPath: BigInt[],
  authIndex: number,
  claimRoot: BigInt,
  revokedClaimRoot: BigInt,
  state: BigInt,
  signatureS: BigInt,
  signatureR8X: BigInt,
  signatureR8Y: BigInt,
  challenge: BigInt
}

export interface IdOwnershipByECDSASignatureWitness {
  publicKeyX: number[],
  publicKeyY: number[],
  authPath: BigInt[],
  authIndex: number,
  claimRoot: BigInt,
  revokedClaimRoot: BigInt,
  state: BigInt,
  signature: number[],
  challenge: BigInt
}

export interface StateTransitionByEDDSASignatureWitness {
  publicKeyX: BigInt,
  publicKeyY: BigInt,
  authPath: BigInt[],
  authIndex: number,
  claimRoot: BigInt,
  revokedClaimRoot: BigInt,
  oldState: BigInt,
  newState: BigInt,
  signatureS: BigInt,
  signatureR8X: BigInt,
  signatureR8Y: BigInt,
  challenge: BigInt
}

export interface StateTransitionByECDSASignatureWitness {
  publicKeyX: number[],
  publicKeyY: number[],
  authPath: BigInt[],
  authIndex: number,
  claimRoot: BigInt,
  revokedClaimRoot: BigInt,
  oldState: BigInt,
  newState: BigInt,
  signature: number[],
  challenge: BigInt
}

export interface ClaimExistenceProofWitness {
  claimPath: BigInt[],
  claimIndex: number,
  claimRoot: BigInt,
  authRoot: BigInt,
  revokedClaimRoot: BigInt,
  issuerState: BigInt
}

export interface ClaimNonRevocationProofWitness {
  pathLow: BigInt[],
  valLow: BigInt,
  nextVal: BigInt,
  nextIdx: number,
  indexLow: number,
  revokedClaimRoot: BigInt,
  authRoot: BigInt,
  claimRoot: BigInt,
  issuerState: BigInt
}

export interface MembershipSetProofWitness {
  setRoot: BigInt,
  setIndex: number,
  setPath: BigInt[]
}

export interface NonMembershipSetProofWitness {
  nmpPathLow: BigInt[],
  nmpValLow: BigInt,
  nmpNextVal: BigInt,
  nmpNextIndex: number,
  nmpIndexLow: number,
  nmpRoot: BigInt
}

export type ECDSASignature = number[];

export interface EDDSAClaimQueryWitness {
  claimSlots: BigInt[],
  iopWitness: IdOwnershipByEDDSASignatureWitness,
  cepWitness: ClaimExistenceProofWitness,
  cnpWitness: ClaimNonRevocationProofWitness,
  schemaHash: BigInt,
  validUntil: BigInt,
  sequel: BigInt,
  subject: BigInt,
  queryType: number,
  slotIndex0: number,
  slotIndex1: number,
  attestingValue: BigInt,
  operator: number,
  mpWitness: MembershipSetProofWitness,
  nmpWitness: NonMembershipSetProofWitness
}

export interface ECDSAClaimQueryWitness {
  claimSlots: BigInt[],
  iopWitness: IdOwnershipByECDSASignatureWitness,
  cepWitness: ClaimExistenceProofWitness,
  cnpWitness: ClaimNonRevocationProofWitness,
  schemaHash: BigInt,
  validUntil: BigInt,
  sequel: BigInt,
  subject: BigInt,
  queryType: number,
  slotIndex0: number,
  slotIndex1: number,
  attestingValue: BigInt,
  operator: number,
  mpWitness: MembershipSetProofWitness,
  nmpWitness: NonMembershipSetProofWitness
}


export interface IssueClaimOperation extends StateTransitionOperation {
  type: "issueClaim",
  claim: Claim
}

export interface RevokeClaimOperation extends StateTransitionOperation {
  type: "revokeClaim",
  claimHash: BigInt
}

export interface AddAuthOperation extends StateTransitionOperation {
  type: "addAuth",
  publicKeyX: BigInt,
  publicKeyY: BigInt,
  publicKeyType: PublicKeyType
}

export interface RevokeAuthOperation extends StateTransitionOperation {
  type: "revokeAuth",
  publicKeyX: BigInt
}

export interface StateTransitionOperation {
  type: string
}

export enum PublicKeyType {
  EDDSA = 1,
  ECDSA = 3,
  None = 0
}

export * as state from "./state/state.js";
export * as indexedMerkleTree from "./tree/indexed-merkle-tree.js";
export * as normalMerkleTree from "./tree/normal-merkle-tree.js";
export * as merkleTree from "./tree/merkle-tree.js";
export * as keys from "./utils/keys.js";
export * as bits from "./utils/bits.js";