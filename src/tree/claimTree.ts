import { Leaf, MerkleTree } from "./merkleTree.js";

class ClaimLeaf implements Leaf {
    public slot: bigint[];

    constructor(slot: bigint[]) {
        if (slot.length == 8) this.slot = slot;
        else this.slot = new Array(8).fill(BigInt(0));
    }

    toNode(hash: Function) {
        return hash([this.slot]);
    };

}

export class ClaimMerkleTree extends MerkleTree {

    public leaves: ClaimLeaf[] = [];

    constructor(n: number, hasher: any) {
        var zeroLeaf = new ClaimLeaf(new Array(8).fill(BigInt(0)));
        super(n, hasher, zeroLeaf);
        this.leaves.push(zeroLeaf);
    }

    insert(leaf: ClaimLeaf) {
        this.leaves.push(leaf);
        this.update(this.leaves.length - 1);
        return this.leaves.length - 1;
    }

}
