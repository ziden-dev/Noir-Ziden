import { expect } from "chai";
import { Issuer } from "./state/state.js";
import {
    getECDSAPublicKeyFromPrivateKey,
    getEDDSAPublicKeyFromPrivateKey,
    stateTransitionByEDDSASignature
} from "./utils/keys.js";
import {
    Crs,
    newBarretenbergApiAsync,
    RawBuffer,
} from "@aztec/bb.js/dest/node/index.js";
import { executeCircuit, compressWitness } from "@noir-lang/acvm_js";
import circuit from "./circuits/state/target/state.json" assert { type: "json" };
import { decompressSync } from "fflate";
import { CryptographyPrimitives } from "./crypto/index.js";
import { AddAuthOperation, IssueClaimOperation, PublicKeyType, RevokeAuthOperation, RevokeClaimOperation } from "./utils/type.js";
import ClaimBuilder from "./claim/claim-builder.js";
import { StateTransitionByEDDSASignatureWitnessBuilder } from "./witness/state-transition-witness-builder.js";

describe("test", () => {
    let poseidon: any;
    let acirBuffer: any;
    let acirBufferUncompressed: any;
    let api: any;
    let acirComposer: any;
    let crypto: CryptographyPrimitives;

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
    });


    it("circuit state transition", async () => {
        var privateKey1 = BigInt("123");
        var privateKey2 = BigInt("12");
        var privateKey3 = BigInt("34");

        var pubkey1 = await getEDDSAPublicKeyFromPrivateKey(privateKey1);
        var pubkey2 = await getEDDSAPublicKeyFromPrivateKey(privateKey2);
        var pubkey3 = getECDSAPublicKeyFromPrivateKey(privateKey3);

        var issuer = new Issuer(3, 3, poseidon);
        issuer.addAuth(pubkey1.X, pubkey1.Y, PublicKeyType.EDDSA);

        var schemaHash = BigInt("93819749189437913473");
        var expirationTime = BigInt(Date.now() + 60 * 60 * 1000);
        var sequel = BigInt(1);
        var subject = BigInt("439798");
        var slotValues = [
            BigInt("43818579187414812304"),
            BigInt("43818579187414812305"),
            BigInt("43818579187414812306"),
            BigInt("43818579187414812307"),
            BigInt("43818579187414812308"),
            BigInt("43818579187414812309"),
        ];
        var claim = new ClaimBuilder()
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

        var operation1: AddAuthOperation = { type: "addAuth", publicKeyX: pubkey2.X, publicKeyY: pubkey2.Y, publicKeyType: PublicKeyType.EDDSA };
        var operation2: AddAuthOperation = { type: "addAuth", publicKeyX: pubkey3.X, publicKeyY: pubkey2.Y, publicKeyType: PublicKeyType.ECDSA };
        var operation3: RevokeAuthOperation = { type: "revokeAuth", publicKeyX: pubkey3.X };
        var operation4: IssueClaimOperation = { type: "issueClaim", claim };
        var operation5: RevokeClaimOperation = { type: "revokeClaim", claimHash: await claim.claimHash() }
        // add pubkey2 and pubkey3 by ecdsa signature
        var inputs = (await stateTransitionByEDDSASignature(
            privateKey1,
            issuer,
            [
                operation1,
                operation2,
                operation3,
                operation4,
                operation5
            ]
        ));

        const witness = new StateTransitionByEDDSASignatureWitnessBuilder(3)
            .withStateTransitionByEDDSASignatureWitness(inputs)
            .build();

        //console.log(witness);

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

    it("circuit state transition", async () => {
        var privateKey1 = BigInt("123");
        var privateKey2 = BigInt("12");
        var privateKey3 = BigInt("34");

        var pubkey1 = await getEDDSAPublicKeyFromPrivateKey(privateKey1);
        var pubkey2 = await getEDDSAPublicKeyFromPrivateKey(privateKey2);
        var pubkey3 = getECDSAPublicKeyFromPrivateKey(privateKey3);

        var issuer = new Issuer(3, 3, poseidon);
        issuer.addAuth(pubkey1.X, pubkey1.Y, PublicKeyType.EDDSA);

        var schemaHash = BigInt("93819749189437913473");
        var expirationTime = BigInt(Date.now() + 60 * 60 * 1000);
        var sequel = BigInt(1);
        var subject = BigInt("439798");
        var slotValues = [
            BigInt("43818579187414812304"),
            BigInt("43818579187414812305"),
            BigInt("43818579187414812306"),
            BigInt("43818579187414812307"),
            BigInt("43818579187414812308"),
            BigInt("43818579187414812309"),
        ];
        var claim = new ClaimBuilder()
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

        var operation1: AddAuthOperation = { type: "addAuth", publicKeyX: pubkey2.X, publicKeyY: pubkey2.Y, publicKeyType: PublicKeyType.EDDSA };
        var operation2: AddAuthOperation = { type: "addAuth", publicKeyX: pubkey3.X, publicKeyY: pubkey2.Y, publicKeyType: PublicKeyType.ECDSA };
        var operation3: RevokeAuthOperation = { type: "revokeAuth", publicKeyX: pubkey3.X };
        var operation4: IssueClaimOperation = { type: "issueClaim", claim };
        var operation5: RevokeClaimOperation = { type: "revokeClaim", claimHash: await claim.claimHash() }
        // add pubkey2 and pubkey3 by ecdsa signature
        var inputs = (await stateTransitionByEDDSASignature(
            privateKey1,
            issuer,
            [
                operation1,
                operation2,
                operation3,
                operation4,
                operation5
            ]
        ));

        const witness = new StateTransitionByEDDSASignatureWitnessBuilder(3)
            .withStateTransitionByEDDSASignatureWitness(inputs)
            .build();

        //console.log(witness);

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
