use dep::std;
mod utils;
mod indexed_merkle_tree;

fn verify<N>(public_key_x: Field,
            public_key_y: Field,
            auth_path: [Field; N],
            auth_index: Field,
            revoked_auth_path: [Field; N],
            revoked_auth_index: Field,
            revoked_auth_value_low: Field,
            revoked_auth_next_value_low: Field,
            revoked_auth_next_index_low: Field,
            revoked_auth_root: Field,
            state: Field,
            signature_s: Field,
            signature_r8_x: Field,
            signature_r8_y:Field,
            challenge: Field ) {
    assert(std::eddsa::eddsa_poseidon_verify(public_key_x ,public_key_y,signature_s,signature_r8_x,signature_r8_y, challenge) == true);
    let auth_leaf = std::hash::poseidon::bn254::hash_2([public_key_x, public_key_y]);
    let auth_root = utils::cal_root_from_mtp(auth_path, auth_leaf, auth_index);
    assert(indexed_merkle_tree::check_non_membership(revoked_auth_path, revoked_auth_value_low, auth_leaf, revoked_auth_next_value_low, 
                                                    revoked_auth_next_index_low, revoked_auth_index, revoked_auth_root) == true);
    assert(std::hash::poseidon::bn254::hash_2([auth_root, revoked_auth_root]) == state);

}

