import { Leaf, MerkleTree } from "./merkle-tree.js";

class IndexedLeaf implements Leaf {
    public val: BigInt;
    public nextVal: BigInt;
    public nextIdx: number;
    constructor(val: BigInt, nextVal: BigInt, nextIdx: number) {
        this.val = val;
        this.nextVal = nextVal;
        this.nextIdx = nextIdx;

    }

    toNode(hash: Function) {
        return hash([this.val, this.nextVal, BigInt(this.nextIdx)]);
    };

}

export class IndexedMerkleTree extends MerkleTree {

    public leaves: IndexedLeaf[] = [];

    constructor(n: number, hasher: any) {
        var initlalLeaf = new IndexedLeaf(0n, 0n, 0);
        super(n, hasher);
        // insert initlal leaf
        this.leaves.push(initlalLeaf);
        this.update(0);
    }

    getLeafLow(value: BigInt) {
        var leafLow = this.leaves[0];
        var idxLow = 0;
        while (true) {
            if (leafLow.nextVal > value || leafLow.nextVal == 0n) break;
            idxLow = leafLow.nextIdx;
            leafLow = this.leaves[leafLow.nextIdx];
        }
        return { idxLow, leafLow }
    }

    getPathProofLow(value: BigInt) {
        var { idxLow, leafLow } = this.getLeafLow(value);

        var { path: pathLow } = this.getPathProof(idxLow);

        return { leafLow, pathLow, idxLow, root: this.getRoot() };
    }


    insert(value: BigInt) {
        // get leaf low
        var res = this.getPathProofLow(value);
        if (res == null) return null;
        var { pathLow, root: rootOld, idxLow, leafLow } = res;

        // check value not exist
        if (leafLow.val == value) return null;
        var leafNew = new IndexedLeaf(value, leafLow.nextVal, leafLow.nextIdx);

        // update leaf low
        leafLow.nextVal = value;
        leafLow.nextIdx = this.leaves.length;
        this.update(idxLow);

        // insert value 
        this.leaves.push(leafNew);
        var idxNew = this.leaves.length - 1;
        this.update(idxNew);

        // get path leaf new
        var res2 = this.getPathProof(idxNew);
        if (res2 == null) return null;
        var { path: pathNew } = res2;
        var rootNew = this.getRoot();

        // return input circuit
        return {
            rootOld,
            rootNew,
            pathLow,
            idxLow,
            valLow: leafLow.val,
            nextValLow: leafNew.nextVal,
            nextIdxLow: leafNew.nextIdx,
            val: value,
            index: idxNew,
            pathNew
        }
    }

}
