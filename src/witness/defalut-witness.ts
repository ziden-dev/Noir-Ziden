import { ClaimExistenceProofWitness, ClaimNonRevocationProofWitness, ECDSAClaimQueryWitness, EDDSAClaimQueryWitness, IdOwnershipByECDSASignatureWitness, IdOwnershipByEDDSASignatureWitness, MembershipSetProofWitness, NonMembershipSetProofWitness, StateTransitionByECDSASignatureWitness, StateTransitionByEDDSASignatureWitness } from "..";

function getDefaultIopEDDSAWitness(n: number) {
    const defaultIopEDDSAWitness: IdOwnershipByEDDSASignatureWitness = {
        publicKeyX: 0n,
        publicKeyY: 0n,
        authPath: new Array(n).fill(0n),
        authIndex: 0,
        claimRoot: 0n,
        revokedClaimRoot: 0n,
        state: 0n,
        signatureS: 0n,
        signatureR8X: 0n,
        signatureR8Y: 0n,
        challenge: 0n
    }
    return defaultIopEDDSAWitness
}

function getDefaultIopECDSAWitness(n: number) {
    const defaultIopECDSAWitness: IdOwnershipByECDSASignatureWitness = {
        publicKeyX: new Array(32).fill(0),
        publicKeyY: new Array(32).fill(0),
        authPath: new Array(n).fill(0n),
        authIndex: 0,
        claimRoot: 0n,
        revokedClaimRoot: 0n,
        state: 0n,
        signature: new Array(64).fill(0),
        challenge: 0n
    }
    return defaultIopECDSAWitness;

}

export function getDefaultStateTransitionEDDSAWitness(n: number) {
    const defaultStateTransitionEDDSAWitness: StateTransitionByEDDSASignatureWitness = {
        publicKeyX: 0n,
        publicKeyY: 0n,
        authPath: new Array(n).fill(0n),
        authIndex: 0,
        claimRoot: 0n,
        revokedClaimRoot: 0n,
        oldState: 0n,
        newState: 0n,
        signatureS: 0n,
        signatureR8X: 0n,
        signatureR8Y: 0n
    }

    return defaultStateTransitionEDDSAWitness;
}

export function getDefaultStateTransitionECDSAWitness(n: number) {
    const defaultStateTransitionECDSAWitness: StateTransitionByECDSASignatureWitness = {
        publicKeyX: new Array(32).fill(0),
        publicKeyY: new Array(32).fill(0),
        authPath: new Array(n).fill(0n),
        authIndex: 0,
        claimRoot: 0n,
        revokedClaimRoot: 0n,
        oldState: 0n,
        newState: 0n,
        signature: new Array(64).fill(0)
    }
    return defaultStateTransitionECDSAWitness;
}

function getDefaultCepWitness(n: number) {
    const defaultCepWitness: ClaimExistenceProofWitness = {
        claimPath: new Array(n).fill(0n),
        claimIndex: 0,
        claimRoot: 0n,
        authRoot: 0n,
        revokedClaimRoot: 0n,
        issuerState: 0n
    }
    return defaultCepWitness;
}

function getDefaultCnpWitness(n: number) {
    const defaultCnpWitness: ClaimNonRevocationProofWitness = {
        pathLow: new Array(n).fill(0n),
        valLow: 0n,
        nextVal: 0n,
        nextIdx: 0,
        indexLow: 0,
        revokedClaimRoot: 0n,
        authRoot: 0n,
        claimRoot: 0n,
        issuerState: 0n
    }

    return defaultCnpWitness;
}

function getDefaultMpWitness(n: number) {
    const defaultMpWitness: MembershipSetProofWitness = {
        setRoot: 0n,
        setIndex: 0,
        setPath: new Array(n).fill(0n)
    }
    return defaultMpWitness;
}

function getDefaultNmpWitness(n: number) {
    const defaultNmpWitness: NonMembershipSetProofWitness = {
        nmpPathLow: new Array(n).fill(0n),
        nmpValLow: 0n,
        nmpNextVal: 0n,
        nmpNextIndex: 0,
        nmpIndexLow: 0,
        nmpRoot: 0n
    }
    return defaultNmpWitness;
}

export function getDefaultEDDSAClaimQueryWitness(nAuth: number, nClaim: number, nSet: number) {
    const defaultEDDSAClaimQueryWitness: EDDSAClaimQueryWitness = {
        claimSlots: new Array(8).fill(0n),
        iopWitness: getDefaultIopEDDSAWitness(nAuth),
        cepWitness: getDefaultCepWitness(nClaim),
        cnpWitness: getDefaultCnpWitness(nClaim),
        schemaHash: 0n,
        validUntil: 0n,
        sequel: 0n,
        subject: 0n,
        queryType: 0,
        slotIndex0: 0,
        slotIndex1: 0,
        attestingValue: 0n,
        operator: 0,
        mpWitness: getDefaultMpWitness(nSet),
        nmpWitness: getDefaultNmpWitness(nSet)
    }
    return defaultEDDSAClaimQueryWitness;
}

export function getDefaultECDSAClaimQueryWitness(nAuth: number, nClaim: number, nSet: number) {
    const defaultECDSAClaimQueryWitness: ECDSAClaimQueryWitness = {
        claimSlots: new Array(8).fill(0n),
        iopWitness: getDefaultIopECDSAWitness(nAuth),
        cepWitness: getDefaultCepWitness(nClaim),
        cnpWitness: getDefaultCnpWitness(nClaim),
        schemaHash: 0n,
        validUntil: 0n,
        sequel: 0n,
        subject: 0n,
        queryType: 0,
        slotIndex0: 0,
        slotIndex1: 0,
        attestingValue: 0n,
        operator: 0,
        mpWitness: getDefaultMpWitness(nSet),
        nmpWitness: getDefaultNmpWitness(nSet)
    }
    return defaultECDSAClaimQueryWitness;
}

