
use dep::std;
use dep::noirlib;

fn main(root_old: pub Field, 
        root_new: pub Field, 
        path_low: [Field; 3], 
        index_low: Field, 
        val_low: Field, 
        next_val_low: Field, 
        next_idx_low:Field, 
        val: Field, 
        index: Field, 
        path_new:[Field;3]) 
    {    
        noirlib::indexed_merkle_tree::insert(
            root_old,
            root_new,
            path_low,
            index_low,
            val_low,
            next_val_low,
            next_idx_low,
            val, 
            index,
            path_new
        );
}