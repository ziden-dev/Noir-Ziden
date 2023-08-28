import { AuthMerkleTree } from "../tree/authTree.js";
import { ClaimMerkleTree } from "../tree/claimTree.js";
import { IndexedMerkleTree } from "../tree/indexedMerkleTree.js";

export abstract class Entity {
    authTree: AuthMerkleTree;

    constructor(n: number, hasher: any) {
        this.authTree = new AuthMerkleTree(n, hasher);
    }


    abstract state(): bigint;
    abstract getAuthProof(publicKeyX: bigint): any;

    addAuth(publicKeyX: bigint, publickeyY: bigint) {
        this.authTree.insert(publicKeyX, publickeyY);
    }

    revokeAuth(publicKeyX: bigint) {
        this.authTree.remove(publicKeyX);
    }


}

export class Holder extends Entity {

    state() {
        return this.authTree.hash([this.authTree.getRoot(), 0n, 0n]);
    }

    getAuthProof(publicKeyX: bigint) {
        return {
            ...this.authTree.getAuthProof(publicKeyX),
            claim_root: 0n,
            revoked_claim_root: 0n,
            state: this.state(),
        };
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

    getAuthProof(publicKeyX: bigint) {
        return {
            ...this.authTree.getAuthProof(publicKeyX),
            claim_root: this.claimTree.getRoot(),
            revoked_claim_root: this.authTree.getRoot(),
            state: this.state(),
        };
    }

    addClaim(slot: bigint[]) {
        this.claimTree.insert(slot);
    }

    revokeClaim(claimHash: bigint) {
        this.revokedClaimTree.insert(claimHash);
    }

}
