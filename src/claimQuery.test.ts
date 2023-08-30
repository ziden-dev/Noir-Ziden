import { expect } from "chai";
import { Holder, Issuer } from "./state/state.js";
import {
    getECDSAPublicKeyFromPrivateKey,
    getEDDSAPublicKeyFromPrivateKey,
    idOwnershipByECDSASignature,
} from "./utils/keys.js";
import {
    Crs,
    newBarretenbergApiAsync,
    RawBuffer,
} from "@aztec/bb.js/dest/node/index.js";
import { executeCircuit, compressWitness } from "@noir-lang/acvm_js";
import circuit from "./circuits/state/target/state.json" assert { type: "json" };
import { decompressSync } from "fflate";
import { convertToHexAndPad, object2Array } from "./utils/bits.js";
import { CryptographyPrimitives } from "./crypto/index.js";
import { PublicKeyType } from "./utils/type.js";
import ClaimBuilder from "./claim/claim-builder.js";
import Claim from "./claim/claim.js";
import { ECDSAPublicKey, EDDSAPublicKey } from "./index.js";

describe("test", () => {
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

    let privateKey1: bigint;
    let privateKey2: bigint;
    let privateKey3: bigint;
    let pubkey1: EDDSAPublicKey;
    let pubkey2: ECDSAPublicKey;
    let pubkey3: ECDSAPublicKey;
    let issuer: Issuer;
    let holder: Holder;
    let challenge: bigint;

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

        holder = new Holder(8, poseidon);
        holder.addAuth(pubkey1.X as bigint, pubkey1.Y as bigint, PublicKeyType.EDDSA);
        holder.addAuth(pubkey2.X as bigint, pubkey2.Y as bigint, PublicKeyType.ECDSA);

        issuer = new Issuer(8, poseidon);
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
    });


    it("circuit query ecdsa claim ", async () => {
        var inputsIOP = await idOwnershipByECDSASignature(privateKey1, holder, challenge);
        var { } = issuer.claimTree.getPathProof(0);
        var inputs: any[] = [];

        const witness = new Map<number, string>();

        inputs.forEach((input, index) => {
            witness.set(index + 1, convertToHexAndPad(input));
        });

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
