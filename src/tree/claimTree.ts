import { Leaf, MerkleTree } from "./merkleTree.js";

class ClaimLeaf implements Leaf {
    public slot: bigint[];

    constructor(slot: bigint[]) {
        if (slot.length == 8) this.slot = slot;
        else this.slot = new Array(8).fill(0n);
    }

    toNode(hash: Function) {
        return hash(this.slot);
    };

}

export class ClaimMerkleTree extends MerkleTree {

    public leaves: ClaimLeaf[] = [];

    constructor(n: number, hasher: any) {

        var zeroLeaf = new ClaimLeaf(new Array(8).fill(0n));
        super(n, hasher, zeroLeaf);
        this.leaves.push(zeroLeaf);
    }

    insert(slot: bigint[]) {
        this.leaves.push(new ClaimLeaf(slot));
        this.update(this.leaves.length - 1);
        return this.leaves.length - 1;
    }

}
