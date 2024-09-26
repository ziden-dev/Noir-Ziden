use dep::std;
use dep::noirlib;

fn main(public_key_x: Field,
            public_key_y: Field,
            auth_path: [Field; 3],
            auth_index: Field,
            claim_root: Field,
            revoked_claim_root: Field,
            old_state: pub Field,
            new_state: pub Field,
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