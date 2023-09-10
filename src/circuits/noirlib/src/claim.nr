// Claim presentation

/* 8 slots:
- Slot 0: 
+ 128 bits: claim shema
+ 64 bits: expiration time
+ 32 bits: sequel

- Slot 1: claim subject
- Slot 2 -> 7: credential data
*/

use dep::std;
mod utils;
mod indexed_merkle_tree;

fn verify_claim_fields(claim: [Field; 8], expected_schema: Field, valid_until: Field, expected_sequel: Field, expected_subject: Field) {
    let slot0bits = claim[0].to_le_bits(254);
    let mut schema_bits = [0; 128];
    for i in 0..128{
        schema_bits[i] = slot0bits[i];
    }
    let actual_schema = utils::from_le_bits(schema_bits);

    let mut expiration_bits = [0; 64];
    for i in 128..192{
        expiration_bits[i - 128] = slot0bits[i];
    }
    let expiration_time = utils::from_le_bits(expiration_bits);

    let mut sequel_bits = [0; 32];
    for i in 192..224{
        sequel_bits[i - 192] = slot0bits[i];
    }
    let actual_sequel = utils::from_le_bits(sequel_bits);
    assert(actual_schema == expected_schema);
    assert(actual_sequel == expected_sequel);
    if(expiration_time != 0){
        assert(utils::less_than(valid_until, expiration_time));
    }
    assert(claim[1] == expected_subject);
}

fn claim_hash(claim: [Field; 8]) -> Field{
    std::hash::poseidon::bn254::hash_8(claim)
}

fn verify_claim_eddsa_signature(
    claim_hash: Field, 
    public_key_x: Field,
    public_key_y: Field,
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field    
) {
    assert(std::eddsa::eddsa_poseidon_verify(public_key_x ,public_key_y,signature_s,signature_r8_x,signature_r8_y, claim_hash) == true);
}

fn verify_claim_ecdsa_signature(
    claim_hash: Field, 
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64]   
) {
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x ,public_key_y,signature, claim_hash.to_le_bytes(32)) == true);
}

fn get_value_claim(claim: [Field; 8], slot_index: u8) -> Field{
    let mut value = 0;
    if (slot_index == 0) { value = claim[0];}
    else if (slot_index == 1) {value = claim[1];}
    else if (slot_index == 2) {value = claim[2];}
    else if (slot_index == 3) {value = claim[3];}
    else if (slot_index == 4) {value = claim[4];}
    else if (slot_index == 5) {value = claim[5];}
    else if (slot_index == 6) {value = claim[6];}
    else if (slot_index == 7) {value = claim[7];}
    assert(slot_index < 8);
    value
}

/*
0: equal
1: greater than
2: less than
*/
fn query_single_value(claim: [Field; 8], slot_index: u8, attesting_value: Field, operator: u8){
    let value = get_value_claim(claim, slot_index);
    if(operator == 0){
        assert(value == attesting_value);
    }else if(operator == 1){
        assert(utils::less_than(value, attesting_value) == true);
    }else if(operator == 2){
        assert(utils::less_than(attesting_value, value) == true);
    }
}

fn query_double_values(claim: [Field; 8], slot_index_0: u8, slot_index_1: u8, operator: u8){
    let value_0 = get_value_claim(claim, slot_index_0);
    let value_1 = get_value_claim(claim, slot_index_1);
    if(operator == 0){
        assert(value_0 == value_1);
    }else if(operator == 1){
        assert(utils::less_than(value_0, value_1) == true);
    }else if(operator == 2){
        assert(utils::less_than(value_1, value_0) == true);
    }
}

fn verify_membership<N>(claim: [Field; 8], slot_index: u8, root: Field, index: Field, merkle_proof: [Field; N]){
    let value = get_value_claim(claim, slot_index);
    let expected_root = utils::cal_root_from_mtp(merkle_proof, value, index);
    assert(expected_root == root);
}

fn verify_non_membership<N>(claim: [Field; 8], slot_index: u8, path_low: [Field; N], val_low: Field, next_val: Field, next_idx: Field, index_low: Field, root: Field){
    let value = get_value_claim(claim, slot_index);
    assert(indexed_merkle_tree::check_non_membership(path_low, val_low, value, next_val, next_idx, index_low, root) == true);
}

