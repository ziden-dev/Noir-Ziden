import { AuthMerkleTree } from "../tree/authTree.js";
import { ClaimMerkleTree } from "../tree/claimTree.js";
import { IndexedMerkleTree } from "../tree/indexedMerkleTree.js";

export abstract class Entity {
    authTree: AuthMerkleTree;

    constructor(n: number, hasher: any) {
        this.authTree = new AuthMerkleTree(n, hasher);
    }

    getAuthProof(publicKeyX: bigint) {
        return {
            ...this.authTree.getAuthProof(publicKeyX),
            state: this.state()
        };
    }

    abstract state(): bigint;

    addAuth(publicKeyX: bigint, publickeyY: bigint) {
        this.authTree.insert(publicKeyX, publickeyY);
    }

    revokeAuth(publicKeyX: bigint) {
        this.authTree.remove(publicKeyX);
    }
}

export class Holder extends Entity {

    state() {
        return this.authTree.getRoot();
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
        return this.authTree.hash([this.authTree.getRoot(), this.claimTree.getRoot(), this.revokedClaimTree.getRoot()]);
    }


}