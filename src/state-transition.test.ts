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
import { AddAuthOperation, IssueClaimOperation, PublicKeyType, RevokeAuthOperation, RevokeClaimOperation } from "./index.js";
import ClaimBuilder from "./claim/claim-builder.js";
import { StateTransitionByEDDSASignatureWitnessBuilder } from "./witness/state-transition-witness-builder.js";
import { ECDSAPublicKey, EDDSAPublicKey } from "./index.js";
import Claim from "./claim/claim.js";




describe("test state transition", () => {
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
    });


    it("circuit state transition", async () => {
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

        const verified = await api.acirVerifyProof(acirComposer, proof, false);

        expect(verified).to.be.true;

    })

    it("circuit state transition", async () => {
        var operation6: RevokeAuthOperation = { type: "revokeAuth", publicKeyX: pubkey2.X };

        var inputs = (await stateTransitionByEDDSASignature(
            privateKey1,
            issuer,
            [
                operation6
            ]
        ));

        const witness = new StateTransitionByEDDSASignatureWitnessBuilder(3)
            .withStateTransitionByEDDSASignatureWitness(inputs)
            .build();



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

        // await api.acirInitProvingKey(acirComposer, acirBufferUncompressed);
        const verified = await api.acirVerifyProof(acirComposer, proof, false);

        expect(verified).to.be.true;

    })
});
