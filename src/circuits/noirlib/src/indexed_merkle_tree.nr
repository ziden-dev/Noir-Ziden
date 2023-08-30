use dep::std;
mod utils;

fn check_low_leaf(pre_val: Field, cur_val: Field, next_val: Field) -> bool {
    utils::less_than(pre_val, cur_val) & ( utils::less_than(cur_val, next_val) | (next_val == 0))
}

fn check_membership<N>(path: [Field; N], val: Field, next_val: Field, next_idx: Field, index: Field, root: Field) -> bool {
    let leaf = std::hash::poseidon::bn254::hash_3([val,next_val,next_idx]);
    utils::cal_root_from_mtp(path,leaf,index) == root
}

fn check_non_membership<N>(path_low: [Field; N], val_low: Field, cur_val: Field, next_val: Field, next_idx: Field, index_low: Field, root: Field) -> bool {
    let leaf_low = std::hash::poseidon::bn254::hash_3([val_low,next_val,next_idx]);
    (utils::cal_root_from_mtp(path_low,leaf_low,index_low) == root) & check_low_leaf(val_low, cur_val, next_val)
}

fn insert<N>(root_old: Field, root_new: Field, path_low: [Field; N], index_low: Field, val_low: Field, next_val_low: Field, 
            next_idx_low:Field, val: Field, index: Field, path_new:[Field;N]) {
    assert(check_non_membership(path_low, val_low, val, next_val_low, next_idx_low, index_low, root_old) == true);
    let new_leaf_low = std::hash::poseidon::bn254::hash_3([val_low, val, index]);
    let cur_root = utils::cal_root_from_mtp(path_low, new_leaf_low, index_low);
    assert(utils::cal_root_from_mtp(path_new,0, index) == cur_root);
    assert(check_membership(path_new, val, next_val_low, next_idx_low, index, root_new) == true);
}
