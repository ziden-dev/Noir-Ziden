use dep::std;
mod utils;
mod indexed_merkle_tree;

fn eddsa_ownership_verify<N>(
            public_key_x: Field,
            public_key_y: Field,
            auth_path: [Field; N],
            auth_index: Field,
            claim_root: Field,
            revoked_claim_root: Field,
            state: Field,
            signature_s: Field,
            signature_r8_x: Field,
            signature_r8_y:Field,
            challenge: Field ) {
    assert(std::eddsa::eddsa_poseidon_verify(public_key_x, public_key_y,signature_s,signature_r8_x,signature_r8_y, challenge) == true);
    let auth_leaf = std::hash::poseidon::bn254::hash_3([public_key_x, public_key_y, 1]);
    let auth_root = utils::cal_root_from_mtp(auth_path, auth_leaf, auth_index);
    let expected_state = std::hash::poseidon::bn254::hash_3([auth_root, claim_root, revoked_claim_root]);
    assert(expected_state == state);
}

fn ecdsa_ownership_verify<N>(
            public_key_x: [u8;32],
            public_key_y: [u8;32],
            auth_path: [Field; N],
            auth_index: Field,
            claim_root: Field,
            revoked_claim_root: Field,
            state: Field,
            signature: [u8; 64],   
            challenge: Field ) {
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x ,public_key_y,signature, challenge.to_le_bytes(32)) == true);
    let auth_leaf = std::hash::poseidon::bn254::hash_3([utils::from_le_bytes(public_key_x), utils::from_le_bytes(public_key_y), 3]);
    let auth_root = utils::cal_root_from_mtp(auth_path, auth_leaf, auth_index);
    let expected_state = std::hash::poseidon::bn254::hash_3([auth_root, claim_root, revoked_claim_root]);
    assert(expected_state == state);
}

