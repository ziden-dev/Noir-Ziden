use dep::std;
mod claim;
mod indexed_merkle_tree;
mod id_ownership_by_signature;
mod utils;
// fn main(root_old: pub Field, root_new: pub Field, path_low: [Field; 3], index_low: Field, val_low: Field, next_val_low: Field, 
//             next_idx_low:Field, val: Field, index: Field, path_new:[Field;3], ) {
//   //std::println(1);
//   indexed_merkle_tree::insert(root_old, root_new, path_low, index_low, val_low, next_val_low,next_idx_low, val, index, path_new);
// }

fn main(public_key_x: [u8;32],
            public_key_y: [u8;32],
            auth_path: [Field; 3],
            auth_index: Field,
            state: Field,
            signature: [u8; 64],   
            challenge: Field   ) {
    let x = -1;
    std::println(x);
    id_ownership_by_signature::verifyECDSA(public_key_x,
            public_key_y,
            auth_path,
            auth_index,
            state,
            signature,
            challenge);
}
