import Claim from "../claim/claim.js"

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