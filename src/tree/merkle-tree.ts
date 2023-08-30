
export interface Leaf {
    toNode: (hash: Function) => BigInt;
}

export class MerkleTree {
    public height: number;
    public node: { [index: number]: BigInt } = {};
    public leaves: Leaf[] = [];
    public hasher: any;
    public zero: BigInt[];

    constructor(n: number, hasher: any) {
        this.height = n;
        this.hasher = hasher;
        this.zero = new Array(n + 1);
        this.hash = this.hash.bind(this);
        this.zero[0] = 0n;

        for (var i = 1; i <= this.height; i++) {
            this.zero[i] = this.hash([this.zero[i - 1], this.zero[i - 1]]);

        }

        this.node[1] = this.zero[n];
    }


    hash(array: BigInt[]) {
        var hash = this.hasher;
        return BigInt(hash.F.toString(hash(array)));
    }

    getRoot() {
        return this.node[1];
    }

    trueIndex(i: number) {
        return i + (1 << this.height);
    }

    leftIndex(i: number) {
        return (i << 1);
    }

    rightIndex(i: number) {
        return (i << 1) + 1;
    }

    parentIndex(i: number) {
        return (i >> 1);
    }

    sibling(i: number) {
        var index = i ^ 1;
        var value = this.getValueNode(index);
        return value;
    }

    getValueNode(index: number) {
        if (this.node[index] != undefined) return this.node[index];
        else {
            for (var i = this.height; i >= 0; i--)
                if ((index >> i) & 1) {
                    return this.zero[this.height - i];
                }
            return this.zero[0];
        }

    }

    update(idx: number) {

        var leaf = this.leaves[idx];
        var index = this.trueIndex(idx);
        var node = this.node;

        node[index] = leaf.toNode(this.hash);

        while (index > 1) {
            index = this.parentIndex(index);
            var indexLeft = this.leftIndex(index);
            var indexRight = this.rightIndex(index);
            node[index] = this.hash([this.getValueNode(indexLeft), this.getValueNode(indexRight)]);
        }
    }

    getPathProof(idx: number) {
        var index = this.trueIndex(idx);
        var value = this.getValueNode(index);
        var path = [];

        while (index > 1) {
            path.push(this.sibling(index));
            index = this.parentIndex(index);
        }

        return { path, index: idx, value }
    }
}