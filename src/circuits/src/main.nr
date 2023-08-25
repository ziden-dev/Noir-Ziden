use dep::std;
mod indexed_merkle_tree;
mod id_ownership_by_signature;
mod utils;
// fn main(root_old: pub Field, root_new: pub Field, path_low: [Field; 3], index_low: Field, val_low: Field, next_val_low: Field, 
//             next_idx_low:Field, val: Field, index: Field, path_new:[Field;3], ) {
//   //std::println(1);
//   indexed_merkle_tree::insert(root_old, root_new, path_low, index_low, val_low, next_val_low,next_idx_low, val, index, path_new);
// }

// fn main(public_key_x: Field,
//             public_key_y: Field,
//             auth_path: [Field; 3],
//             auth_index: Field,
//             revoked_auth_path: [Field; 3],
//             revoked_auth_index: Field,
//             revoked_auth_value_low: Field,
//             revoked_auth_next_value_low: Field,
//             revoked_auth_next_index_low: Field,
//             revoked_auth_root: Field,
//             state: Field,
//             signature_s: Field,
//             signature_r8_x: Field,
//             signature_r8_y:Field,
//             challenge: Field  ) {

//     id_ownership_by_signature::verify(public_key_x,
//             public_key_y,
//             auth_path,
//             auth_index,
//             revoked_auth_path,
//             revoked_auth_index,
//             revoked_auth_value_low,
//             revoked_auth_next_value_low,
//             revoked_auth_next_index_low,
//             revoked_auth_root,
//             state,
//             signature_s,
//             signature_r8_x,
//             signature_r8_y,
//             challenge);
// }

fn main(public_key_x : Field, public_key_y : Field, signature: [Field; 2], message_hash: Field) {
        //public_key_x : [u8; 32], public_key_y : [u8; 32], signature: [u8; 64], message_hash: [u8; 32]
        let _public_key_x = [0;32];
        let _public_key_y = [0;32];
        let _signature = [0;64];
        let _message_hash =[0;32];
        utils::fields_to_u8_array([public_key_x],_public_key_x);
        utils::fields_to_u8_array([public_key_y],_public_key_y);
        utils::fields_to_u8_array([],_public_key_y);
        assert(std::ecdsa_secp256k1::verify_signature(_public_key_x,_public_key_y,_signature,_message_hash) == true);
}