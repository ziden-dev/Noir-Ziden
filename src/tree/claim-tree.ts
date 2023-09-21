import Claim from "../claim/claim.js";
import { Leaf, MerkleTree } from "./merkle-tree.js";

class ClaimLeaf implements Leaf {
    public claim: Claim;

    constructor(claim: Claim) {
        this.claim = claim;
    }

    toNode(hash: Function) {
        return this.claim.claimHashCustom(hash);
    };

}

export class ClaimMerkleTree extends MerkleTree {

    public leaves: ClaimLeaf[] = [];

    insert(claim: Claim) {
        this.leaves.push(new ClaimLeaf(claim));
        this.update(this.leaves.length - 1);
        return this.leaves.length - 1;
    }

    getIndex(claimHash: BigInt) {
        for (var i = 0; i < this.leaves.length; i++) {
            var node = this.node[this.trueIndex(i)];
            if (node == claimHash) return i;
        }
        return 0;
    }
}
