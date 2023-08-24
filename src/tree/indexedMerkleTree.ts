import { Leaf, MerkleTree } from "./merkleTree.js";

class IndexedLeaf implements Leaf {
    public val: bigint;
    public nextVal: bigint;
    public nextIdx: number;
    constructor(val: bigint, nextVal: bigint, nextIdx: number) {
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
        var zeroLeaf = new IndexedLeaf(0n, 0n, 0);
        super(n, hasher, zeroLeaf);
        this.leaves.push(zeroLeaf);
    }

    getLeafLow(value: bigint) {
        var leafLow = this.leaves[0];
        var idxLow = 0;
        while (true) {
            if (leafLow.nextVal > value || leafLow.nextVal == 0n) break;
            idxLow = leafLow.nextIdx;
            leafLow = this.leaves[leafLow.nextIdx];
        }
        return { idxLow, leafLow }
    }

    getPathProofLow(value: bigint) {
        var { idxLow, leafLow } = this.getLeafLow(value);

        var { path: pathLow } = this.getPathProof(idxLow);

        return { leafLow, pathLow, idxLow, root: this.getRoot() };
    }


    insert(value: bigint) {
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
            path_low: pathLow,
            root_old: rootOld,
            index_low: idxLow,
            val_low: leafLow.val,
            next_val_low: leafNew.nextVal,
            next_idx_low: leafNew.nextIdx,
            val: value,
            index: idxNew,
            path_new: pathNew,
            root_new: rootNew
        }
    }

    // insert_batch(m, values) {
    //     values.sort();
    //     var idxNew = this.leaves.length;
    //     var p = values.length;

    //     if (idxNew % p != 0 || (1 << m) != p) {
    //         return;
    //     }

    //     var pathLow = [];
    //     var idxLow = [];
    //     var valLow = [];
    //     var nextValLow = [];
    //     var nextIdxLow = [];

    //     var valNew = [];
    //     var nextValNew = [];
    //     var nextIdxNew = [];
    //     var rootOld = this.getRoot();
    //     // insert to pending subtree

    //     for (var i = 0; i < p; i++) {
    //         var value = values[i];
    //         var { idxLow: curIndexLow, leafLow } = this.getLeafLow(value);
    //         if (leafLow.val == value) return;
    //         ///
    //         var { path } = this.getPath(leafLow.val);
    //         idxLow.push(curIndexLow);
    //         pathLow.push(path);
    //         valLow.push(leafLow.val);
    //         nextValLow.push(leafLow.nextVal);
    //         nextIdxLow.push(leafLow.nextIdx);
    //         ///
    //         var leafNew = { val: value, nextVal: leafLow.nextVal, nextIdx: leafLow.nextIdx };
    //         leafLow.nextVal = value;
    //         leafLow.nextIdx = this.leaves.length;
    //         this.leaves.push(leafNew);
    //         if (curIndexLow < idxNew) this.update(curIndexLow);

    //         valNew.push(leafNew.val);

    //     }

    //     for (var i = 0; i < p; i++) {
    //         var leaf = this.leaves[i + idxNew];

    //         nextValNew.push(leaf.nextVal);
    //         nextIdxNew.push(leaf.nextIdx);
    //     }

    //     // insert subtree

    //     //      get path

    //     var index = this.trueIndex(idxNew) >> m;


    //     var pathNew = [];
    //     while (index > 1) {
    //         pathNew.push(this.sibling(index));
    //         index = this.parentIndex(index);
    //     }



    //     //    insert subtree
    //     for (var i = 0; i < p; i++) {
    //         this.update(idxNew + i);
    //     }

    //     index = this.trueIndex(idxNew) >> m;



    //     var rootNew = this.getRoot();
    //     return {
    //         pathLow,
    //         rootOld,
    //         indexLow: idxLow,
    //         valLow,
    //         nextValLow,
    //         nextIdxLow,

    //         rootOld,
    //         rootNew,

    //         indexNew: idxNew,
    //         pathNew,
    //         valNew,
    //         nextValNew,
    //         nextIdxNew
    //     }
    // }
}
