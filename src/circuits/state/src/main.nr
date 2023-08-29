use dep::std;
use dep::noirlib;

fn main(public_key_x: [u8;32],
            public_key_y: [u8;32],
            auth_path: [Field; 3],
            auth_index: Field,
            claim_root: Field,
            revoked_claim_root: Field,
            old_state: Field,
            new_state: Field,
            signature_s: Field,
            signature_r8_x: Field,
            signature_r8_y: Field) {
    noirlib::state_transition::eddsa_state_verify(
            public_key_x,
            public_key_y,
            auth_path,
            auth_index,
            claim_root,
            revoked_claim_root,
            old_state,
            new_state,
            signature_s,
            signature_r8_x,
            signature_r8_y);
}