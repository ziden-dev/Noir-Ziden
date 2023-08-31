# Noir-Ziden

This is the proof-of-concept project of Ziden protocol with circuits written in Noir

In this first version, we have completed the Noir circuits, test scripts as well as the TS scripts that serve the protocol's logic as specified in the [Protocol-specs](https://github.com/ziden-dev/Noir-Ziden/tree/main/specs)

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

Digital signatures are used in the protocol as a principal authorization mechanism, in this version, we support 2 algorithms:

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

## Future work

- Solidity smart contracts for proof verification and identity state management

- User interface for holders

- Server for issuers

- Server and smart contracts for verfiers

