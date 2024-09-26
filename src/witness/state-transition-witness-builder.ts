import { convertToHexAndPad, flattenObject } from "../utils/bits.js";
import { StateTransitionByECDSASignatureWitness, StateTransitionByEDDSASignatureWitness } from "../index.js";
import { getDefaultStateTransitionECDSAWitness, getDefaultStateTransitionEDDSAWitness } from "./defalut-witness.js";

export class StateTransitionByECDSASignatureWitnessBuilder {
    private witness: StateTransitionByECDSASignatureWitness;

    constructor(n: number) {
        this.witness = getDefaultStateTransitionECDSAWitness(n);
    }

    withStateTransitionByECDSASignatureWitness(witness: StateTransitionByECDSASignatureWitness) {
        this.witness = witness;
        return this;
    }

    withPublicKey(publicKeyX: number[], publicKeyY: number[]) {
        this.witness.publicKeyX = publicKeyX;
        this.witness.publicKeyY = publicKeyY;
        return this;
    }

    withAuthPath(authPath: BigInt[]) {
        this.witness.authPath = authPath;
        return this;
    }

    withAuthIndex(authIndex: number) {
        this.witness.authIndex = authIndex;
        return this;
    }

    withClaimRoot(claimRoot: BigInt) {
        this.witness.claimRoot = claimRoot;
        return this;
    }

    withRevokedClaimRoot(revokedClaimRoot: BigInt) {
        this.witness.revokedClaimRoot = revokedClaimRoot;
        return this;
    }

    withOldState(oldState: BigInt) {
        this.witness.oldState = oldState;
        return this;
    }

    withNewState(newState: BigInt) {
        this.witness.newState = newState;
        return this;
    }

    withSignature(signature: number[]) {
        this.witness.signature = signature;
        return this;
    }

    build(): Map<number, string> {
        const witnessMap = new Map<number, string>();
        var inputs = flattenObject(this.witness);
        inputs.forEach((input, index) => {
            witnessMap.set(index + 1, convertToHexAndPad(input));
        });
        return witnessMap;
    }
}


export class StateTransitionByEDDSASignatureWitnessBuilder {
    private witness: StateTransitionByEDDSASignatureWitness;

    constructor(n: number) {
        this.witness = getDefaultStateTransitionEDDSAWitness(n);
    }

    withStateTransitionByEDDSASignatureWitness(witness: StateTransitionByEDDSASignatureWitness) {
        this.witness = witness;
        return this;
    }


    withPublicKey(publicKeyX: BigInt, publicKeyY: BigInt) {
        this.witness.publicKeyX = publicKeyX;
        this.witness.publicKeyY = publicKeyY;
        return this;
    }

    withAuthPath(authPath: BigInt[]) {
        this.witness.authPath = authPath;
        return this;
    }

    withAuthIndex(authIndex: number) {
        this.witness.authIndex = authIndex;
        return this;
    }

    withClaimRoot(claimRoot: BigInt) {
        this.witness.claimRoot = claimRoot;
        return this;
    }

    withRevokedClaimRoot(revokedClaimRoot: BigInt) {
        this.witness.revokedClaimRoot = revokedClaimRoot;
        return this;
    }

    withOldState(oldState: BigInt) {
        this.witness.oldState = oldState;
        return this;
    }

    withNewState(newState: BigInt) {
        this.witness.newState = newState;
        return this;
    }

    withSignatureS(signatureS: BigInt) {
        this.witness.signatureS = signatureS;
        return this;
    }

    withSignatureR8X(signatureR8X: BigInt) {
        this.witness.signatureR8X = signatureR8X;
        return this;
    }

    withSignatureR8Y(signatureR8Y: BigInt) {
        this.witness.signatureR8Y = signatureR8Y;
        return this;
    }

    build(): Map<number, string> {
        const witnessMap = new Map<number, string>();
        var inputs = flattenObject(this.witness);
        inputs.forEach((input, index) => {
            witnessMap.set(index + 1, convertToHexAndPad(input));
        });
        return witnessMap;
    }
}
