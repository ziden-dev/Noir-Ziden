import { bigInt2BytesLE } from "../crypto/wasmcurves/utils.js";
import { Leaf, MerkleTree } from "./merkleTree.js";

class AuthLeaf implements Leaf {
    public publicKeyX: bigint;
    public publicKeyY: bigint;

    constructor(publicKeyX: bigint, publicKeyY: bigint) {
        this.publicKeyX = publicKeyX;
        this.publicKeyY = publicKeyY;
    }

    toNode(hash: Function) {
        return hash([this.publicKeyX, this.publicKeyY]);
    };

}


export class AuthMerkleTree extends MerkleTree {

    public leaves: AuthLeaf[] = [];

    constructor(n: number, hasher: any) {
        var zeroLeaf = new AuthLeaf(0n, 0n);
        super(n, hasher, zeroLeaf);
        this.leaves.push(zeroLeaf);
    }

    insert(publicKeyX: bigint, publicKeyY: bigint) {
        this.leaves.push(new AuthLeaf(publicKeyX, publicKeyY));
        this.update(this.leaves.length - 1);
        return this.leaves.length - 1;
    }

    remove(publicKeyX: bigint) {
        for (const [index, leaf] of this.leaves.entries()) {
            if (leaf.publicKeyX == publicKeyX) {
                leaf.publicKeyX = 0n;
                leaf.publicKeyY = 0n;
                this.update(index);
                break;
            }
        }
    }

    getAuthProof(publicKeyX: bigint) {
        var publicKeyY;
        var authPath;
        var authIndex;
        for (const [index, leaf] of this.leaves.entries()) {
            if (leaf.publicKeyX == publicKeyX) {
                publicKeyY = leaf.publicKeyY;
                authPath = this.getPathProof(index).path;
                authIndex = index;
                break;
            }
        }
        if (publicKeyY == null || authPath == null || authIndex == null) return null;

        return {
            public_key_x: bigInt2BytesLE(publicKeyX, 32),
            public_key_y: bigInt2BytesLE(publicKeyY, 32),
            auth_path: authPath,
            auth_index: authIndex
        }
    }
}
