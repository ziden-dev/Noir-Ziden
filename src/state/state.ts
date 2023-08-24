import { AuthMerkleTree } from "../tree/authTree.js";
import { ClaimMerkleTree } from "../tree/claimTree.js";
import { IndexedMerkleTree } from "../tree/indexedMerkleTree.js";

export abstract class Entity {
    authTree: AuthMerkleTree;
    revokedAuthTree: IndexedMerkleTree;

    constructor(n: number, hasher: any) {
        this.authTree = new AuthMerkleTree(n, hasher);
        this.revokedAuthTree = new IndexedMerkleTree(n, hasher);
    }

    getAuthProof(publicKeyX: bigint) {
        var publicKeyY;
        var authPath;
        var authIndex;
        for (const [index, leaf] of this.authTree.leaves.entries()) {
            if (leaf.publicKeyX == publicKeyX) {
                publicKeyY = leaf.publicKeyY;
                authPath = this.authTree.getPathProof(index).path;
                authIndex = index;
                break;
            }
        }
        if (publicKeyY == null || authPath == null || authIndex == null) return null;

        var value = this.authTree.hash([publicKeyX, publicKeyY]);
        var { leafLow, pathLow, idxLow } = this.revokedAuthTree.getPathProofLow(value);
        return {
            public_key_x: publicKeyX,
            public_key_y: publicKeyY,
            auth_path: authPath,
            auth_index: authIndex,
            revoked_auth_path: pathLow,
            revoked_auth_index: idxLow,
            revoked_auth_value_low: leafLow.val,
            revoked_auth_next_value_low: leafLow.nextVal,
            revoked_auth_next_index_low: leafLow.nextIdx,
            revoked_auth_root: this.revokedAuthTree.getRoot(),
            state: this.state()
        }
    }

    abstract state(): bigint;

    addAuth(publicKeyX: bigint, publickeyY: bigint) {
        this.authTree.insert(publicKeyX, publickeyY);
    }

    revokeAuth(publicKeyX: bigint, publickeyY: bigint) {
        this.revokedAuthTree.insert(this.authTree.hash([publicKeyX, publickeyY]));
    }
}

export class Holder extends Entity {

    state() {
        return this.authTree.hash([this.authTree.getRoot(), this.revokedAuthTree.getRoot()]);
    }

}

export class Issuer extends Entity {
    claimTree: ClaimMerkleTree;
    revokedClaimTree: IndexedMerkleTree;

    constructor(n: number, hasher: any) {
        super(n, hasher);
        this.claimTree = new ClaimMerkleTree(n, hasher);
        this.revokedClaimTree = new IndexedMerkleTree(n, hasher);
    }

    state() {
        return this.authTree.hash([this.authTree.getRoot(), this.revokedAuthTree.getRoot(),
        this.claimTree.getRoot(), this.revokedClaimTree.getRoot()]);
    }


}