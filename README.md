# Noir-Ziden

This is the proof-of-concept project of the Privacy-Preserving W3C verifiable credentials protocol with circuits written in Noir

In this first version contains completent Noir circuits, test scripts as well as the TS scripts that serve the protocol's logic as specified in the [Protocol-specs](https://github.com/ziden-dev/Noir-Ziden/tree/main/specs)

## Components

### 1. Merkle Tree & Indexed Merkle Tree

They are core data structure of the protocol, enabling succinct membership and non-membership verification, currently supporting:

- Membership check
- Non-membership check
- Single insertion

[See circuit](https://github.com/ziden-dev/Noir-Ziden/blob/main/src/circuits/noirlib/src/indexed_merkle_tree.nr)

Upcoming features:

- Variable arity
- Batch insertion

### 2. Digital Signature

Digital signatures are used in the protocol as a principal authorization mechanism, this version supports 2 algorithms:

- EdDSA
- ECDSA

### 3. Protocol circuits

- [Claim](https://github.com/ziden-dev/Noir-Ziden/blob/main/src/circuits/noirlib/src/claim.nr)

- [Identity State](https://github.com/ziden-dev/Noir-Ziden/blob/main/src/circuits/noirlib/src/state_transition.nr)

- [Claim Presentation](https://github.com/ziden-dev/Noir-Ziden/blob/main/src/circuits/noirlib/src/claim_presentation.nr)

## Run our code

### Prerequisite

- Node version >= 16
- Nargo installed: [See installation guide](https://noir-lang.org/getting_started/nargo_installation)

### Installation

- Install dependencies:

```
npm i
```

- Compile Noir circuits:

```
./compile.sh
```

### Test

- Test claim features

```
npm run test-claim
```

- Test indexed merkle tree features

```
npm run test-indexed-merkle-tree
```

- Test state features

```
npm run test-state
```

- Test claim presentation process

```
npm run test-claim-query
```

## Use this as a library

- Install as an npm dependency:

```
npm i @chung0807/noir-ziden@latest
```

### Indexed Merkle Tree

- Construct a new Indexed Merkle Tree

```typescript
import {
  CryptographyPrimitives,
  IndexedMerkleTree,
  bitUtils,
  generateProofAndVerify,
  CircuitName,
} from "@chung0807/noir-ziden";

const crypto = await CryptographyPrimitives.getInstance();
const poseidon = crypto.poseidon;

// tree with depth being 3 and use Poseidon as hasher
const tree = new IndexedMerkleTree(3, poseidon);
```

- Test, generate and verify ZK proof

```typescript
tree.insert(3n);
var inputs = bitUtils.object2Array(tree.insert(1n));

const witness = new Map<number, string>();

inputs.forEach((input, index) => {
  witness.set(index + 1, convertToHexAndPad(input));
});

const verified = await generateProofAndVerify(
  witness,
  CircuitName.INDEXED_MERKLE_TREE
);

assert(verified == true);
```

### Claim

Technically, a claim is an array of 8 32-byte numbers called slots, which can be constructed customizably with the following information:

- Schema hash
- The sequel number (in case there are multiple claims included in a single schema)
- The expired time
- The claim subject
- Credential data (can be stored from slot 2 to 7)

Example:

```typescript
import { ClaimBuilder } from "@chung0807/noir-ziden";

const schemaHash = BigInt("43914"); // should be the hash of the schema document
const expirationTime = BigInt(Date.now() + 60 * 60 * 1000);
const sequel = BigInt(1);
const subject = BigInt("439798"); // should be the Id of its holder

const claim = new ClaimBuilder()
  .withSchemaHash(schemaHash)
  .withExpirationTime(expirationTime)
  .withSequel(sequel)
  .withSubject(subject)
  .withSlotValue(2, BigInt("1"))
  .withSlotValue(3, BigInt("2"))
  .withSlotValue(4, BigInt("3"))
  .withSlotValue(5, BigInt("4"))
  .withSlotValue(6, BigInt("5"))
  .withSlotValue(7, BigInt("6"))
  .build();
```

We also can read, set information and perform logics of a claim after it is generated through its below functions:

```typescript
get schemaHash() {}

get sequel() {}

get expirationTime() {}

get subject() {}

get allSlots() {}

async claimHash() {}

async eddsaSign(privateKey: BigInt){}

async ecdsaSign(privateKey: BigInt){}

getSlotValue(index: number) {}

clone() {}

set schemaHash(schemaHash: BigInt) {}

set sequel(sequel: BigInt) {}

set expirationTime(expirationTime: BigInt) {}

set subject(subject: BigInt) {}

setSlotValue(index: number, value: BigInt) {}
```

### Holder

To create a holder in the protocol, you only need a set of either EDDSA or ECDSA public keys.

A holder can perform 2 operations to change its state

- Add a new key
- Revoked an existing key

```typescript
import {
  keyUtils,
  Holder,
  AddAuthOperation,
  StateTransitionByEDDSASignatureWitnessBuilder,
  generateProofAndVerify,
  CircuitName,
} from "@chung0807/noir-ziden";

const {
  getEDDSAPublicKeyFromPrivateKey,
  getECDSAPublicKeyFromPrivateKey,
  stateTransitionByEDDSASignature,
} = keyUtils;
var privateKey1 = BigInt("123");
var privateKey2 = BigInt("12");
var privateKey3 = BigInt("34");

// eddsa
var pubkey1 = await getEDDSAPublicKeyFromPrivateKey(privateKey1);
var pubkey2 = await getEDDSAPublicKeyFromPrivateKey(privateKey2);

// ecdsa
var pubkey3 = getECDSAPublicKeyFromPrivateKey(privateKey3);

const holder = new Holder(3, poseidon);

await holder.addAuth(pubkey1.X, pubkey1.Y, PublicKeyType.EDDSA);

// commit key insertion through the ZK proof
var operation1: AddAuthOperation = {
  type: "addAuth",
  publicKeyX: pubkey2.X,
  publicKeyY: pubkey2.Y,
  publicKeyType: PublicKeyType.EDDSA,
};
var operation2: AddAuthOperation = {
  type: "addAuth",
  publicKeyX: pubkey3.X,
  publicKeyY: pubkey2.Y,
  publicKeyType: PublicKeyType.ECDSA,
};

var inputs = await stateTransitionByEDDSASignature(privateKey1, issuer, [
  operation1,
  operation2,
]);

const witness = new StateTransitionByEDDSASignatureWitnessBuilder(3)
  .withStateTransitionByEDDSASignatureWitness(inputs)
  .build();

const verified = await generateProofAndVerify(witness, CircuitName.STATE);

assert(verified == true);
```

### Issuer

Apart from key sets, an issuer also maintain a set of claims it has granted for holders and a set of revoked claims.

A issuer can perform 4 operations to change its state

- Add a new key
- Revoked an existing key
- Issue a new claim
- Revoke an existing claim

```typescript
import {
  keyUtils,
  Issuer,
  AddAuthOperation,
  StateTransitionByEDDSASignatureWitnessBuilder,
  generateProofAndVerify,
  CircuitName,
  ClaimBuilder,
} from "@chung0807/noir-ziden";

const {
  getEDDSAPublicKeyFromPrivateKey,
  getECDSAPublicKeyFromPrivateKey,
  stateTransitionByEDDSASignature,
} = keyUtils;
var privateKey1 = BigInt("123");
var privateKey2 = BigInt("12");
var privateKey3 = BigInt("34");

// eddsa
var pubkey1 = await getEDDSAPublicKeyFromPrivateKey(privateKey1);
var pubkey2 = await getEDDSAPublicKeyFromPrivateKey(privateKey2);

// ecdsa
var pubkey3 = getECDSAPublicKeyFromPrivateKey(privateKey3);

var schemaHash = BigInt("93819749189437913473");
var expirationTime = BigInt(Date.now() + 60 * 60 * 1000);
var sequel = BigInt(1);
var subject = BigInt("439798");
var slotValues = [
  BigInt("43818579187414812304"),
  BigInt("43818579187414812305"),
  BigInt("43818579187414812306"),
  BigInt("43818579187414812307"),
  BigInt("43818579187414812308"),
  BigInt("43818579187414812309"),
];
var claim = new ClaimBuilder()
  .withSchemaHash(schemaHash)
  .withExpirationTime(expirationTime)
  .withSequel(sequel)
  .withSubject(subject)
  .withSlotValue(2, slotValues[0])
  .withSlotValue(3, slotValues[1])
  .withSlotValue(4, slotValues[2])
  .withSlotValue(5, slotValues[3])
  .withSlotValue(6, slotValues[4])
  .withSlotValue(7, slotValues[5])
  .build();

const issuer = new Issuer(3, poseidon);

await issuer.addAuth(pubkey1.X, pubkey1.Y, PublicKeyType.EDDSA);

// commit key insertion through the ZK proof
var operation1: AddAuthOperation = {
  type: "addAuth",
  publicKeyX: pubkey2.X,
  publicKeyY: pubkey2.Y,
  publicKeyType: PublicKeyType.EDDSA,
};
var operation2: AddAuthOperation = {
  type: "addAuth",
  publicKeyX: pubkey3.X,
  publicKeyY: pubkey3.Y,
  publicKeyType: PublicKeyType.ECDSA,
};
var operation3: RevokeAuthOperation = {
  type: "revokeAuth",
  publicKeyX: pubkey3.X,
};
var operation4: IssueClaimOperation = { type: "issueClaim", claim };
var operation5: RevokeClaimOperation = {
  type: "revokeClaim",
  claimHash: await claim.claimHash(),
};

var inputs = await stateTransitionByEDDSASignature(privateKey1, issuer, [
  operation1,
  operation2,
  operation3,
  operation4,
  operation5,
]);

const witness =
  new stateTransitionWitnessBuilder.StateTransitionByEDDSASignatureWitnessBuilder(
    3
  )
    .withStateTransitionByEDDSASignatureWitness(inputs)
    .build();

const verified = await generateProofAndVerify(witness, CircuitName.STATE);

assert(verified == true);
```

### Claim presentation

```typescript
import {
  Claim,
  ClaimBuilder,
  EDDSAPublicKey,
  ECDSAPublicKey,
  Issuer,
  Holder,
  ClaimExistenceProofWitness,
  ClaimNonRevocationProofWitness,
  ECDSAPublicKey,
  EDDSAPublicKey,
  IdOwnershipByECDSASignatureWitness,
  MembershipSetProofWitness,
  NonMembershipSetProofWitness,
  generateProofAndVerify,
  CircuitName,
  ECDSAClaimQueryWitnessBuilder,
} from "@chung0807/noir-ziden";

let claim: Claim;

let schemaHash: BigInt;
let expirationTime: BigInt;
let sequel: BigInt;
let slotValues: BigInt[];
let subject: BigInt;

let privateKey1: BigInt;
let privateKey2: BigInt;
let privateKey3: BigInt;
let pubkey1: EDDSAPublicKey;
let pubkey2: ECDSAPublicKey;
let pubkey3: ECDSAPublicKey;
let issuer: Issuer;
let holder: Holder;
let challenge: BigInt;

let iopWitness: IdOwnershipByECDSASignatureWitness;
let cepWitness: ClaimExistenceProofWitness;
let cnpWitness: ClaimNonRevocationProofWitness;
let mpWitness: MembershipSetProofWitness;
let nmpWitness: NonMembershipSetProofWitness;

privateKey1 = BigInt("123");
privateKey2 = BigInt("12");
privateKey3 = BigInt("12");

pubkey1 = await getEDDSAPublicKeyFromPrivateKey(privateKey1);
pubkey2 = getECDSAPublicKeyFromPrivateKey(privateKey2);
pubkey3 = getECDSAPublicKeyFromPrivateKey(privateKey3);

holder = new Holder(8, poseidon);
holder.addAuth(pubkey1.X, pubkey1.Y, PublicKeyType.EDDSA);
holder.addAuth(pubkey2.X, pubkey2.Y, PublicKeyType.ECDSA);

issuer = new Issuer(8, 10, poseidon);
issuer.addAuth(pubkey3.X as bigint, pubkey3.Y as bigint, PublicKeyType.ECDSA);

schemaHash = BigInt("93819749189437913473");
expirationTime = BigInt(Date.now() + 60 * 60 * 1000);
sequel = BigInt(1);
subject = BigInt("439798");
slotValues = [
  BigInt("43818579187414812304"),
  BigInt("43818579187414812305"),
  BigInt("43818579187414812306"),
  BigInt("43818579187414812307"),
  BigInt("43818579187414812308"),
  BigInt("43818579187414812309"),
];
claim = new ClaimBuilder()
  .withSchemaHash(schemaHash)
  .withExpirationTime(expirationTime)
  .withSequel(sequel)
  .withSubject(subject)
  .withSlotValue(2, slotValues[0])
  .withSlotValue(3, slotValues[1])
  .withSlotValue(4, slotValues[2])
  .withSlotValue(5, slotValues[3])
  .withSlotValue(6, slotValues[4])
  .withSlotValue(7, slotValues[5])
  .build();

issuer.addClaim(claim);
challenge = BigInt("123");

mpWitness = await MembershipSetProof(
  6,
  poseidon,
  [claim.getSlotValue(0).valueOf(), 12n],
  0
);
nmpWitness = await NonMembershipSetProof(
  6,
  poseidon,
  [1n, 123123123123123n],
  claim.getSlotValue(0).valueOf()
);

iopWitness = await idOwnershipByECDSASignature(privateKey2, holder, challenge);
cepWitness = await ClaimExistenceProof(issuer, 0);
cnpWitness = await ClaimNonRevocationProof(issuer, await claim.claimHash());

const validUntil = BigInt(Date.now() + 30 * 60 * 1000);

var witness = new ECDSAClaimQueryWitnessBuilder(8, 10, 6)
  .withClaimSlots(claim.allSlots)
  .withECDSAIopWitness(iopWitness)
  .withCepWitness(cepWitness)
  .withCnpWitness(cnpWitness)
  .withAttestingValue(claim.getSlotValue(0).valueOf() + BigInt(1))
  .withOperator(1)
  .withQueryType(0)
  .withSlotIndex0(0)
  .withSchemaHash(schemaHash)
  .withSequel(sequel)
  .withSubject(subject)
  .withValidUntil(validUntil)
  .build();

const verified = await generateProofAndVerify(
  witness,
  CircuitName.ECDSA_CLAIM_PRESENTATION
);

assert(verified == true);
```
## Benchmark circuits

| Name | Size | 
|----------|----------|
| ecdsa claim presentation circuit size (nAuth = 3, nClaim = 3, nSet = 2) | 103009 | 
| eddsa claim presentation circuit size (nAuth = 3, nClaim = 3, nSet = 2) | 101401 | 
| ecdsa state transition circuit size (nAuth = 3) | 50029 |
| eddsa state transition circuit size (nAuth = 3) | 48507 |
| insert indexed merkle tree circuit size (n = 3) | 39303 |

## Future work

- Solidity smart contracts for proof verification and identity state management

- User interface for holders

- Server for issuers

- Server and smart contracts for verfiers
