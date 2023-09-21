import { Holder, Issuer } from "./state/state.js";
import {
    ClaimExistenceProof,
    ClaimNonRevocationProof,
    MembershipSetProof,
    NonMembershipSetProof,
    getECDSAPublicKeyFromPrivateKey,
    getEDDSAPublicKeyFromPrivateKey,
    idOwnershipByEDDSASignature,
    stateTransitionByEDDSASignature
} from "./utils/keys.js";
import { AddAuthOperation, CircuitName, ClaimExistenceProofWitness, ClaimNonRevocationProofWitness, CryptographyPrimitives, IdOwnershipByEDDSASignatureWitness, MembershipSetProofWitness, NonMembershipSetProofWitness, PublicKeyType, RevokeAuthOperation } from "./index.js";
import ClaimBuilder from "./claim/claim-builder.js";
import { StateTransitionByEDDSASignatureWitnessBuilder } from "./witness/state-transition-witness-builder.js";
import { ECDSAPublicKey, EDDSAPublicKey } from "./index.js";
import Claim from "./claim/claim.js";
import { Contract, ethers } from 'ethers'; // example using ethers v5
import stateVerifierArtifacts from './artifacts/src/contracts/StateVerifier.sol/UltraVerifier.json' assert { type: "json" };
import stateArtifacts from './artifacts/src/contracts/State.sol/State.json' assert { type: "json" };
import queryVerifiersArtifacts from './artifacts/src/contracts/QueryVerifier.sol/UltraVerifier.json' assert { type: "json" };
import queryArtifacts from './artifacts/src/contracts/Query.sol/Query.json'  assert { type: "json" };
import { EDDSAClaimQueryWitnessBuilder } from "./witness/claim-query-witness-builder.js";
import { generateProof } from "./berretenberg-api/index.js";

describe("test contract", () => {
    let poseidon: any;
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

    let provider: any;
    let wallet: any;
    let stateContract: Contract;
    let queryContract: Contract;
    let queryVerifierContract: Contract;

    let challenge: BigInt;
    let validUntil: BigInt;
    let iopWitness: IdOwnershipByEDDSASignatureWitness;
    let cepWitness: ClaimExistenceProofWitness;
    let cnpWitness: ClaimNonRevocationProofWitness;
    let mpWitness: MembershipSetProofWitness;
    let nmpWitness: NonMembershipSetProofWitness;


    before(async () => {
        crypto = await CryptographyPrimitives.getInstance();
        poseidon = crypto.poseidon;
        privateKey1 = BigInt("123");
        privateKey2 = BigInt("12");
        privateKey3 = BigInt("34");

        pubkey1 = await getEDDSAPublicKeyFromPrivateKey(privateKey1);
        pubkey2 = await getEDDSAPublicKeyFromPrivateKey(privateKey2);
        pubkey3 = getECDSAPublicKeyFromPrivateKey(privateKey3);

        issuer = new Issuer(3, 3, poseidon);
        issuer.addAuth(pubkey1.X, pubkey1.Y, PublicKeyType.EDDSA);

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

        holder = new Holder(3, poseidon);
        holder.addAuth(pubkey2.X, pubkey2.Y, PublicKeyType.EDDSA);

        provider = ethers.getDefaultProvider('http://127.0.0.1:8545');
        wallet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
        const stateVerifierFactory = new ethers.ContractFactory(stateVerifierArtifacts.abi, stateVerifierArtifacts.bytecode, wallet);
        const stateVerifierContract = await stateVerifierFactory.deploy();

        const stateFactory = new ethers.ContractFactory(stateArtifacts.abi, stateArtifacts.bytecode, wallet);
        stateContract = await stateFactory.deploy();
        await stateContract.initialize(stateVerifierContract.address);

        const queryVerifierFactory = new ethers.ContractFactory(queryVerifiersArtifacts.abi, queryVerifiersArtifacts.bytecode, wallet);
        queryVerifierContract = await queryVerifierFactory.deploy();

        const queryFactory = new ethers.ContractFactory(queryArtifacts.abi, queryArtifacts.bytecode, wallet);
        queryContract = await queryFactory.deploy();
        await queryContract.initialize(queryVerifierContract.address, stateContract.address);

        issuer.addClaim(claim);

        challenge = BigInt("123");
        validUntil = BigInt(Date.now() + 30 * 60 * 1000);

        mpWitness = await MembershipSetProof(2, poseidon, [claim.getSlotValue(0).valueOf(), 12n], 0);
        nmpWitness = await NonMembershipSetProof(2, poseidon, [1n, 123123123123123n], claim.getSlotValue(0).valueOf());
        cepWitness = await ClaimExistenceProof(issuer, await claim.claimHash());

    });


    it("state transition", async () => {
        var operation1: AddAuthOperation = { type: "addAuth", publicKeyX: pubkey3.X, publicKeyY: pubkey2.Y, publicKeyType: PublicKeyType.ECDSA };
        var operation2: RevokeAuthOperation = { type: "revokeAuth", publicKeyX: pubkey3.X };

        // add pubkey2 and pubkey3 by ecdsa signature
        var inputs = (await stateTransitionByEDDSASignature(
            privateKey1,
            issuer,
            [
                operation1,
                operation2
            ]
        ));

        const witness = new StateTransitionByEDDSASignatureWitnessBuilder(3)
            .withStateTransitionByEDDSASignatureWitness(inputs)
            .build();

        var proof = await generateProof(witness, CircuitName.STATE);

        await stateContract.transitState(1, true, proof.slicedProof, proof.publicInputs);
    })

    it("contract query type 0 ecdsa claim ", async () => {

        cnpWitness = await ClaimNonRevocationProof(issuer, await claim.claimHash());
        iopWitness = await idOwnershipByEDDSASignature(privateKey2, holder, challenge);
        const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

        cnpWitness = await ClaimNonRevocationProof(issuer, await claim.claimHash());

        var witness = new EDDSAClaimQueryWitnessBuilder(3, 3, 2)
            .withClaimSlots(claim.allSlots)
            .withEDDSAIopWitness(iopWitness)
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

        var proof = await generateProof(witness, CircuitName.EDDSA_CLAIM_PRESENTATION);


        await queryContract.verify(2, 1, proof.slicedProof, proof.publicInputs);
    });

    it("contract query type 1 ecdsa claim ", async () => {
        var witness = new EDDSAClaimQueryWitnessBuilder(3, 3, 2)
            .withClaimSlots(claim.allSlots)
            .withEDDSAIopWitness(iopWitness)
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

        var proof = await generateProof(witness, CircuitName.EDDSA_CLAIM_PRESENTATION);

        await queryContract.verify(2, 1, proof.slicedProof, proof.publicInputs);
    });

    it("contract query type 2 ecdsa claim ", async () => {
        var witness = new EDDSAClaimQueryWitnessBuilder(3, 3, 2)
            .withClaimSlots(claim.allSlots)
            .withEDDSAIopWitness(iopWitness)
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

        var proof = await generateProof(witness, CircuitName.EDDSA_CLAIM_PRESENTATION);

        await queryContract.verify(2, 1, proof.slicedProof, proof.publicInputs);
    });

    it("contract query type 3 ecdsa claim ", async () => {
        var witness = new EDDSAClaimQueryWitnessBuilder(3, 3, 2)
            .withClaimSlots(claim.allSlots)
            .withEDDSAIopWitness(iopWitness)
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

        var proof = await generateProof(witness, CircuitName.EDDSA_CLAIM_PRESENTATION);

        await queryContract.verify(2, 1, proof.slicedProof, proof.publicInputs);
    });
});
