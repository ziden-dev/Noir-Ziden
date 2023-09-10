import { expect } from "chai";
import { Holder, Issuer } from "./state/state.js";
import {
    ClaimExistenceProof,
    ClaimNonRevocationProof,
    MembershipSetProof,
    NonMembershipSetProof,
    getECDSAPublicKeyFromPrivateKey,
    getEDDSAPublicKeyFromPrivateKey,
    idOwnershipByEDDSASignature,
} from "./utils/keys.js";
import {
    Crs,
    newBarretenbergApiAsync,
    RawBuffer,
} from "@aztec/bb.js/dest/node/index.js";
import { executeCircuit, compressWitness } from "@noir-lang/acvm_js";
import circuit from "./circuits/eddsa_claim_presentation/target/eddsa_claim_presentation.json" assert { type: "json" };
import { decompressSync } from "fflate";
import { CryptographyPrimitives } from "./crypto/index.js";
import { IdOwnershipByEDDSASignatureWitness, PublicKeyType } from "./index.js";
import ClaimBuilder from "./claim/claim-builder.js";
import Claim from "./claim/claim.js";
import { ClaimExistenceProofWitness, ClaimNonRevocationProofWitness, ECDSAPublicKey, EDDSAPublicKey, MembershipSetProofWitness, NonMembershipSetProofWitness } from "./index.js";
import { EDDSAClaimQueryWitnessBuilder } from "./witness/claim-query-witness-builder.js";


describe("test claim query", () => {
    let poseidon: any;
    let acirBuffer: any;
    let acirBufferUncompressed: any;
    let api: any;
    let acirComposer: any;
    let crypto: CryptographyPrimitives;

    let claim: Claim;

    let schemaHash: BigInt;
    let expirationTime: BigInt;
    let sequel: BigInt;
    let slotValues: BigInt[];
    let subject: BigInt;

    let privateKey1: BigInt;
    let privateKey2: BigInt;
    let privateKey3: BigInt;
    let pubkey1: EDDSAPublicKey;
    let pubkey2: ECDSAPublicKey;
    let pubkey3: ECDSAPublicKey;
    let issuer: Issuer;
    let holder: Holder;
    let challenge: BigInt;

    let iopWitness: IdOwnershipByEDDSASignatureWitness;
    let cepWitness: ClaimExistenceProofWitness;
    let cnpWitness: ClaimNonRevocationProofWitness;
    let mpWitness: MembershipSetProofWitness;
    let nmpWitness: NonMembershipSetProofWitness;

    before(async () => {
        crypto = await CryptographyPrimitives.getInstance();
        poseidon = crypto.poseidon;
        acirBuffer = Buffer.from(circuit.bytecode, "base64");
        acirBufferUncompressed = decompressSync(acirBuffer);
        api = await newBarretenbergApiAsync(4);
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

        acirComposer = await api.acirNewAcirComposer(subgroupSize);

        privateKey1 = BigInt("123");
        privateKey2 = BigInt("12");
        privateKey3 = BigInt("12");

        pubkey1 = await getEDDSAPublicKeyFromPrivateKey(privateKey1);
        pubkey2 = getECDSAPublicKeyFromPrivateKey(privateKey2);
        pubkey3 = getECDSAPublicKeyFromPrivateKey(privateKey3);

        holder = new Holder(3, poseidon);
        holder.addAuth(pubkey1.X, pubkey1.Y, PublicKeyType.EDDSA);
        holder.addAuth(pubkey2.X, pubkey2.Y, PublicKeyType.ECDSA);

        issuer = new Issuer(3, 3, poseidon);
        issuer.addAuth(pubkey3.X as bigint, pubkey3.Y as bigint, PublicKeyType.ECDSA)

        schemaHash = BigInt("93819749189437913473");
        expirationTime = BigInt(Date.now() + 60 * 60 * 1000);
        sequel = BigInt(1);
        subject = BigInt("439798");
        slotValues = [
            BigInt("43818579187414812304"),
            BigInt("43818579187414812305"),
            BigInt("43818579187414812306"),
            BigInt("43818579187414812307"),
            BigInt("43818579187414812308"),
            BigInt("43818579187414812309"),
        ];
        claim = new ClaimBuilder()
            .withSchemaHash(schemaHash)
            .withExpirationTime(expirationTime)
            .withSequel(sequel)
            .withSubject(subject)
            .withSlotValue(2, slotValues[0])
            .withSlotValue(3, slotValues[1])
            .withSlotValue(4, slotValues[2])
            .withSlotValue(5, slotValues[3])
            .withSlotValue(6, slotValues[4])
            .withSlotValue(7, slotValues[5])
            .build();

        issuer.addClaim(claim);
        challenge = BigInt("123");

        mpWitness = await MembershipSetProof(2, poseidon, [claim.getSlotValue(0).valueOf(), 12n], 0);
        nmpWitness = await NonMembershipSetProof(2, poseidon, [1n, 123123123123123n], claim.getSlotValue(0).valueOf());

        iopWitness = await idOwnershipByEDDSASignature(privateKey1, holder, challenge);
        cepWitness = await ClaimExistenceProof(issuer, 0);
        cnpWitness = await ClaimNonRevocationProof(issuer, await claim.claimHash());
    });


    it("circuit query type 0 ecdsa claim ", async () => {
        const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

        var witness = new EDDSAClaimQueryWitnessBuilder(3, 3, 2)
            .withClaimSlots(claim.allSlots)
            .withECDSAIopWitness(iopWitness)
            .withCepWitness(cepWitness)
            .withCnpWitness(cnpWitness)
            .withAttestingValue(claim.getSlotValue(0).valueOf() + BigInt(1))
            .withOperator(1)
            .withQueryType(0)
            .withSlotIndex0(0)
            .withSchemaHash(schemaHash)
            .withSequel(sequel)
            .withSubject(subject)
            .withValidUntil(validUntil)
            .build()

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

        expect(verified).to.be.true;

    });

    it("circuit query type 1 ecdsa claim ", async () => {
        const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

        var witness = new EDDSAClaimQueryWitnessBuilder(3, 3, 2)
            .withClaimSlots(claim.allSlots)
            .withECDSAIopWitness(iopWitness)
            .withCepWitness(cepWitness)
            .withCnpWitness(cnpWitness)
            .withSlotIndex1(3)
            .withOperator(1)
            .withQueryType(1)
            .withSlotIndex0(2)
            .withSchemaHash(schemaHash)
            .withSequel(sequel)
            .withSubject(subject)
            .withValidUntil(validUntil)
            .build()

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

        expect(verified).to.be.true;

    });

    it("circuit query type 2 ecdsa claim", async () => {
        const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

        var witness = new EDDSAClaimQueryWitnessBuilder(3, 3, 2)
            .withClaimSlots(claim.allSlots)
            .withECDSAIopWitness(iopWitness)
            .withCepWitness(cepWitness)
            .withCnpWitness(cnpWitness)
            .withQueryType(2)
            .withSlotIndex0(0)
            .withSchemaHash(schemaHash)
            .withSequel(sequel)
            .withSubject(subject)
            .withValidUntil(validUntil)
            .withMpWitness(mpWitness)
            .build()

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

        expect(verified).to.be.true;

    })

    it("circuit query type 3 ecdsa claim", async () => {
        const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

        var witness = new EDDSAClaimQueryWitnessBuilder(3, 3, 2)
            .withClaimSlots(claim.allSlots)
            .withECDSAIopWitness(iopWitness)
            .withCepWitness(cepWitness)
            .withCnpWitness(cnpWitness)
            .withQueryType(3)
            .withSlotIndex0(0)
            .withSchemaHash(schemaHash)
            .withSequel(sequel)
            .withSubject(subject)
            .withValidUntil(validUntil)
            .withNmpWitness(nmpWitness)
            .build()

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

        expect(verified).to.be.true;

    })

});
