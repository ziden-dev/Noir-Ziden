import { expect } from "chai";
import { buildPoseidon } from "./crypto/poseidon_wasm.js"
import { IndexedMerkleTree } from "./tree/indexedMerkleTree.js";
import { Holder } from "./state/state.js";
import { getEDDSAPublicKeyFromPrivateKey, stateTransitionByEDDSASignature } from "./witness/authen.js";
import { prove_and_verify } from "./utils/runCircuit.js";

describe("test", () => {
    let poseidon: any;
    before(async () => {
        poseidon = await buildPoseidon();
    })

    it("poseidon", async () => {
        const res = poseidon([1, 2]);
        expect(poseidon.F.toString(res)).equal(BigInt("0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a").toString(10));
    })

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

    })

    // it("circuit insert tree", async () => {

    //     //   root
    //     //    /\
    //     //   a  zero[2]
    //     //  /  \    
    //     // b    c
    //     // /\   /\
    //     //0  3 1  zero[0]
    //     //1  0 3
    //     //2  0 1

    //     var tree = new IndexedMerkleTree(3, poseidon);

    //     tree.insert(3n);
    //     var input = tree.insert(1n);

    //     if (input != null) prove_and_verify(input);

    // })

    it("circuit id ownership by signature", async () => {

        var privateKey1 = BigInt("123");
        var privateKey2 = BigInt("12");
        var privateKey3 = BigInt("34");

        var pubkey1 = await getEDDSAPublicKeyFromPrivateKey(privateKey1);
        var pubkey2 = await getEDDSAPublicKeyFromPrivateKey(privateKey2);
        var pubkey3 = await getEDDSAPublicKeyFromPrivateKey(privateKey3);

        var holder = new Holder(3, poseidon);
        holder.addAuth(pubkey1.publicKeyX, pubkey1.publicKeyY);

        var input = await stateTransitionByEDDSASignature(
            privateKey1,
            holder,
            [
                { type: "addAuthOperation", ...pubkey2 },
                { type: "addAuthOperation", ...pubkey3 },
                { type: "revokeAuthOperation", ...pubkey3 },
            ]
        )

        if (input != null) prove_and_verify(input);
    })

    // it("circuit id ownership by signature", async () => {

    //     const messageHash = Buffer.alloc(32, 2);
    //     const prvKey = Buffer.alloc(32, 1);

    //     // const messageHash = Buffer.from(sha256(message).slice(2), "hex");

    //     const pubKey = publicKeyCreate(prvKey, false);

    //     const pubKeyX = pubKey.slice(1, 33);
    //     const pubKeyY = pubKey.slice(33, 65);

    //     const ret = ecdsaSign(messageHash, prvKey);

    //     // console.log(messageHash);

    //     // console.log(pubKeyX, pubKeyY);

    //     // console.log(ret);

    //     var input = {
    //         _public_key_x: Array.from(pubKeyX),
    //         _public_key_y: Array.from(pubKeyY),
    //         _signature: Array.from(ret.signature),
    //         _message_hash: messageHash
    //     }

    //     prove_and_verify(input);
    //     // const recovered = ecdsaRecover(ret.signature, ret.recid, message);
    // })
})




