import { expect } from "chai";
import { IndexedMerkleTree } from "./tree/indexed-merkle-tree.js";
import {
    Crs,
    newBarretenbergApiAsync,
    RawBuffer,
} from "@aztec/bb.js/dest/node/index.js";
import { executeCircuit, compressWitness } from "@noir-lang/acvm_js";
import circuit from "./circuits/indexed_merkle_tree/target/indexed_merkle_tree.json" assert { type: "json" };
import { decompressSync } from "fflate";
import { convertToHexAndPad, object2Array } from "./utils/bits.js";
import { CryptographyPrimitives } from "./crypto/index.js";


describe("test indexed merkle tree", () => {
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


    it("poseidon", async () => {
        const res = poseidon([1, 2]);
        expect(poseidon.F.toString(res)).equal(
            BigInt(
                "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
            ).toString(10)
        );
    });

    it("js insert tree", async () => {
        //   root
        //    /\
        //   a  zero[2]
        //  /  \
        // b    c
        // /\   /\
        //0  3 1  zero[0]
        //1  0 3
        //2  0 1

        var tree = new IndexedMerkleTree(3, poseidon);

        tree.insert(3n);
        tree.insert(1n);

        var leaf1 = tree.hash([0n, 1n, 2n]);
        var leaf2 = tree.hash([3n, 0n, 0n]);
        var leaf3 = tree.hash([1n, 3n, 1n]);

        var c = tree.hash([leaf3, tree.zero[0]]);
        var b = tree.hash([leaf1, leaf2]);
        var a = tree.hash([b, c]);
        var root = tree.hash([a, tree.zero[2]]);

        expect(root).equal(tree.getRoot());

        /// check path
        var res = tree.getPathProofLow(1n);
        if (res != null) {
            var { leafLow: leaf, pathLow: path } = res;
            var leaf4 = tree.hash([leaf.val, leaf.nextVal, BigInt(leaf.nextIdx)]);
            var c2 = tree.hash([leaf4, path[0]]);
            var a2 = tree.hash([path[1], c2]);
            var root2 = tree.hash([a2, path[2]]);

            expect(root).equal(root2);
        }
    });

    it("circuit insert tree", async () => {


        var tree = new IndexedMerkleTree(3, poseidon);

        tree.insert(3n);

        var inputs = object2Array(tree.insert(1n));

        const witness = new Map<number, string>();

        inputs.forEach((input, index) => {
            witness.set(index + 1, convertToHexAndPad(input));
        });


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
