#!/bin/bash

cd src/circuits/claim
echo "Compiling the claim circuit..."
nargo compile
echo "Successfully compiled the claim circuit"

cd ../indexed_merkle_tree
echo "Compiling the index merkle tree circuit..."
nargo compile
echo "Successfully compiled the index merkle tree circuit"

cd ../eddsa_state_transition
echo "Compiling the state circuit..."
nargo compile
echo "Successfully compiled the eddsa state transition circuit"

cd ../ecdsa_state_transition
echo "Compiling the state circuit..."
nargo compile
echo "Successfully compiled the ecdsa state transition circuit"

cd ../eddsa_claim_presentation
echo "Compiling the eddsa claim presentation circuit..."
nargo compile
echo "Successfully compiled the eddsa claim presentation circuit"

cd ../ecdsa_claim_presentation
echo "Compiling the ecdsa claim presentation circuit..."
nargo compile
echo "Successfully compiled the ecdsa claim presentation circuit"