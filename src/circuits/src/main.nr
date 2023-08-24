use dep::std;
mod indexed_merkle_tree;
mod id_ownership_by_signature;
// fn main(root_old: pub Field, root_new: pub Field, path_low: [Field; 3], index_low: Field, val_low: Field, next_val_low: Field, 
//             next_idx_low:Field, val: Field, index: Field, path_new:[Field;3], ) {
//   //std::println(1);
//   indexed_merkle_tree::insert(root_old, root_new, path_low, index_low, val_low, next_val_low,next_idx_low, val, index, path_new);
// }

fn main(public_key_x: Field,
            public_key_y: Field,
            auth_path: [Field; 3],
            auth_index: Field,
            revoked_auth_path: [Field; 3],
            revoked_auth_index: Field,
            revoked_auth_value_low: Field,
            revoked_auth_next_value_low: Field,
            revoked_auth_next_index_low: Field,
            revoked_auth_root: Field,
            state: Field,
            signature_s: Field,
            signature_r8_x: Field,
            signature_r8_y:Field,
            challenge: Field  ) {

    id_ownership_by_signature::verify(public_key_x,
            public_key_y,
            auth_path,
            auth_index,
            revoked_auth_path,
            revoked_auth_index,
            revoked_auth_value_low,
            revoked_auth_next_value_low,
            revoked_auth_next_index_low,
            revoked_auth_root,
            state,
            signature_s,
            signature_r8_x,
            signature_r8_y,
            challenge);
}