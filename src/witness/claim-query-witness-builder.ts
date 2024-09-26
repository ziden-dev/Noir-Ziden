import { ClaimExistenceProofWitness, ClaimNonRevocationProofWitness, ECDSAClaimQueryWitness, EDDSAClaimQueryWitness, IdOwnershipByECDSASignatureWitness, IdOwnershipByEDDSASignatureWitness, MembershipSetProofWitness, NonMembershipSetProofWitness } from "../index.js";
import { convertToHexAndPad, flattenObject } from "../utils/bits.js";
import { getDefaultECDSAClaimQueryWitness, getDefaultEDDSAClaimQueryWitness } from "./defalut-witness.js";

export class ECDSAClaimQueryWitnessBuilder {
    private witness: ECDSAClaimQueryWitness;

    constructor(nAuth: number, nClaim: number, nSet: number) {
        this.witness = getDefaultECDSAClaimQueryWitness(nAuth, nClaim, nSet);
    }

    withClaimSlots(slots: BigInt[]) {
        this.witness.claimSlots = slots;
        return this;
    }

    withECDSAIopWitness(iopWitness: IdOwnershipByECDSASignatureWitness) {
        this.witness.iopWitness = iopWitness;
        return this;
    }

    withCepWitness(cepWitness: ClaimExistenceProofWitness) {
        this.witness.cepWitness = cepWitness;
        return this;
    }

    withCnpWitness(cnpWitness: ClaimNonRevocationProofWitness) {
        this.witness.cnpWitness = cnpWitness;
        return this;
    }

    withValidUntil(validUntil: BigInt) {
        this.witness.validUntil = validUntil;
        return this;
    }

    withSchemaHash(schemaHash: BigInt) {
        this.witness.schemaHash = schemaHash;
        return this;
    }


    withSequel(sequel: BigInt) {
        this.witness.sequel = sequel;
        return this;
    }

    withSubject(subject: BigInt) {
        this.witness.subject = subject;
        return this;
    }

    withQueryType(queryType: number) {
        this.witness.queryType = queryType;
        return this;
    }

    withSlotIndex0(slotIndex0: number) {
        this.witness.slotIndex0 = slotIndex0;
        return this;
    }

    withSlotIndex1(slotIndex1: number) {
        this.witness.slotIndex1 = slotIndex1;
        return this;
    }

    withAttestingValue(attestingValue: BigInt) {
        this.witness.attestingValue = attestingValue;
        return this;
    }

    withOperator(operator: number) {
        this.witness.operator = operator;
        return this;
    }

    withMpWitness(mpWitness: MembershipSetProofWitness) {
        this.witness.mpWitness = mpWitness;
        return this;
    }

    withNmpWitness(nmpWitness: NonMembershipSetProofWitness) {
        this.witness.nmpWitness = nmpWitness;
        return this;
    }

    build(): Map<number, string> {
        console.log
        const witnessMap = new Map<number, string>();
        var inputs = flattenObject(this.witness);
        inputs.forEach((input, index) => {
            witnessMap.set(index + 1, convertToHexAndPad(input));
        });
        return witnessMap;
    }
}




export class EDDSAClaimQueryWitnessBuilder {
    private witness: EDDSAClaimQueryWitness;

    constructor(nAuth: number, nClaim: number, nSet: number) {
        this.witness = getDefaultEDDSAClaimQueryWitness(nAuth, nClaim, nSet);
    }

    withClaimSlots(slots: BigInt[]) {
        this.witness.claimSlots = slots;
        return this;
    }

    withEDDSAIopWitness(iopWitness: IdOwnershipByEDDSASignatureWitness) {
        this.witness.iopWitness = iopWitness;
        return this;
    }

    withCepWitness(cepWitness: ClaimExistenceProofWitness) {
        this.witness.cepWitness = cepWitness;
        return this;
    }

    withCnpWitness(cnpWitness: ClaimNonRevocationProofWitness) {
        this.witness.cnpWitness = cnpWitness;
        return this;
    }

    withSchemaHash(schemaHash: BigInt) {
        this.witness.schemaHash = schemaHash;
        return this;
    }

    withValidUntil(validUntil: BigInt) {
        this.witness.validUntil = validUntil;
        return this;
    }

    withSequel(sequel: BigInt) {
        this.witness.sequel = sequel;
        return this;
    }

    withSubject(subject: BigInt) {
        this.witness.subject = subject;
        return this;
    }

    withQueryType(queryType: number) {
        this.witness.queryType = queryType;
        return this;
    }

    withSlotIndex0(slotIndex0: number) {
        this.witness.slotIndex0 = slotIndex0;
        return this;
    }

    withSlotIndex1(slotIndex1: number) {
        this.witness.slotIndex1 = slotIndex1;
        return this;
    }

    withAttestingValue(attestingValue: BigInt) {
        this.witness.attestingValue = attestingValue;
        return this;
    }

    withOperator(operator: number) {
        this.witness.operator = operator;
        return this;
    }

    withMpWitness(mpWitness: MembershipSetProofWitness) {
        this.witness.mpWitness = mpWitness;
        return this;
    }

    withNmpWitness(nmpWitness: NonMembershipSetProofWitness) {
        this.witness.nmpWitness = nmpWitness;
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
