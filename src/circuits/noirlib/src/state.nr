use dep::std;
mod utils;
mod claim;
mod indexed_merkle_tree;

fn check_claim_existence<N>(claim_hash: Field, merkle_path: [Field; N], claim_index: Field, claim_root: Field) {
    let actual_root = utils::cal_root_from_mtp(merkle_path, claim_hash, claim_index);
    assert(actual_root == claim_root);
}

fn check_claim_nonrevocation<N>(claim_hash: Field, path_low: [Field; N], val_low: Field, next_val: Field, next_idx: Field, index_low: Field, revocation_root: Field){
    assert(indexed_merkle_tree::check_non_membership(path_low, val_low, claim_hash, next_val, next_idx, index_low, revocation_root) == true);
}

fn check_eddsa_key_existence<N>(public_key_x: Field, public_key_y: Field, auth_path: [Field; N], auth_index: Field, auth_root: Field){
    let auth_hash = std::hash::poseidon::bn254::hash_3([public_key_x, public_key_y, 1]);
    let actual_root = utils::cal_root_from_mtp(auth_path, auth_hash, auth_index);
    assert(actual_root == auth_root);
}

fn check_ecdsa_key_existence<N>(public_key_x: [u8; 32], public_key_y: [u8; 32], auth_path: [Field; N], auth_index: Field, auth_root: Field){
    let auth_hash = std::hash::poseidon::bn254::hash_3([utils::from_le_bytes(public_key_x), utils::from_le_bytes(public_key_y), 3]);
    let actual_root = utils::cal_root_from_mtp(auth_path, auth_hash, auth_index);
    assert(actual_root == auth_root);
}

fn check_identity_state(auth_root: Field, claim_root: Field, revocation_root: Field, identity_state: Field){
    let expected_state = std::hash::poseidon::bn254::hash_3([auth_root, claim_root, revocation_root]);
    assert(expected_state == identity_state);
}