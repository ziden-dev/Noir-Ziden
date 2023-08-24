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

}
