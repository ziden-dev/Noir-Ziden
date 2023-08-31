import { PublicKeyType } from "../index.js";
import { AuthMerkleTree } from "../tree/auth-tree.js";
import { ClaimMerkleTree } from "../tree/claim-tree.js";
import { IndexedMerkleTree } from "../tree/indexed-merkle-tree.js";
import Claim from "../claim/claim.js";

export abstract class Entity {
    authTree: AuthMerkleTree;

    constructor(n: number, hasher: any) {
        this.authTree = new AuthMerkleTree(n, hasher);
    }


    abstract state(): BigInt;
    abstract getAuthProof(publicKeyX: BigInt): any;

    addAuth(publicKeyX: BigInt, publickeyY: BigInt, publicKeyType: PublicKeyType) {
        this.authTree.insert(publicKeyX, publickeyY, publicKeyType);
    }

    revokeAuth(publicKeyX: BigInt) {
        this.authTree.remove(publicKeyX);
    }


}

export class Holder extends Entity {

    state() {
        return this.authTree.hash([this.authTree.getRoot(), 0n, 0n]);
    }

    getAuthProof(publicKeyX: BigInt) {
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

    constructor(nAuthTree: number, nClaimTree: number, hasher: any) {
        super(nAuthTree, hasher);
        this.claimTree = new ClaimMerkleTree(nClaimTree, hasher);
        this.revokedClaimTree = new IndexedMerkleTree(nClaimTree, hasher);
    }

    state() {
        return this.authTree.hash([this.authTree.getRoot(), this.claimTree.getRoot(), this.revokedClaimTree.getRoot()]);
    }

    getAuthProof(publicKeyX: BigInt) {
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

    revokeClaim(claimHash: BigInt) {
        this.revokedClaimTree.insert(claimHash);
    }
}
