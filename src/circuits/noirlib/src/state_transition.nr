use dep::std;
mod id_ownership_by_signature;

fn eddsa_state_verify<N>(
            public_key_x: Field,
            public_key_y: Field,
            auth_path: [Field; N],
            auth_index: Field,
            claim_root: Field,
            revoked_claim_root: Field,
            old_state: Field,
            new_state: Field,
            signature_s: Field,
            signature_r8_x: Field,
            signature_r8_y:Field) {
    let challenge = std::hash::poseidon::bn254::hash_2([old_state, new_state]);
    id_ownership_by_signature::eddsa_ownership_verify(
        public_key_x,
        public_key_y,
        auth_path,
        auth_index,
        claim_root,
        revoked_claim_root,
        old_state,
        signature_s,
        signature_r8_x,
        signature_r8_y,
        challenge
    )
}

fn ecdsa_state_verify<N>(
            public_key_x: [u8;32],
            public_key_y: [u8;32],
            auth_path: [Field; N],
            auth_index: Field,
            claim_root: Field,
            revoked_claim_root: Field,
            old_state: Field,
            new_state: Field,
            signature: [u8; 64]) {
    let challenge = std::hash::poseidon::bn254::hash_2([old_state, new_state]);
    id_ownership_by_signature::ecdsa_ownership_verify(
        public_key_x,
        public_key_y,
        auth_path,
        auth_index,
        claim_root,
        revoked_claim_root,
        old_state,
        signature,
        challenge
    )
}


