export interface IssueClaimOperation extends StateTransitionOperation {
    type: "issueClaim",
    slot: bigint[]
}

export interface RevokeClaimOperation extends StateTransitionOperation {
    type: "revokeClaim",
    claimHash: bigint
}

export interface AddAuthOperation extends StateTransitionOperation {
    type: "addAuth",
    publicKeyX: bigint,
    publicKeyY: bigint
}

export interface RevokeAuthOperation extends StateTransitionOperation {
    type: "revokeClaim",
    publicKeyX: bigint
}

export interface StateTransitionOperation {
    type: string
}
