import { PublicKeyType } from "../utils/type.js";
import { AuthMerkleTree } from "../tree/authTree.js";
import { ClaimMerkleTree } from "../tree/claimTree.js";
import { IndexedMerkleTree } from "../tree/indexedMerkleTree.js";
import Claim from "../claim/claim.js";

export abstract class Entity {
    authTree: AuthMerkleTree;

    constructor(n: number, hasher: any) {
        this.authTree = new AuthMerkleTree(n, hasher);
    }


    abstract state(): bigint;
    abstract getAuthProof(publicKeyX: bigint): any;

    addAuth(publicKeyX: bigint, publickeyY: bigint, publicKeyType: PublicKeyType) {
        this.authTree.insert(publicKeyX, publickeyY, publicKeyType);
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
            claimRoot: 0n,
            revokedClaimRoot: 0n,
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
            claimRoot: this.claimTree.getRoot(),
            revokedClaimRoot: this.revokedClaimTree.getRoot(),
            state: this.state(),
        };
    }

    addClaim(claim: Claim) {
        this.claimTree.insert(claim);
    }

    revokeClaim(claimHash: bigint) {
        this.revokedClaimTree.insert(claimHash);
    }

    getClaimProof() {

    }
}
