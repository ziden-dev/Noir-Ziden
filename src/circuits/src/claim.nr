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
    let actual_schema = utils::from_le_bits(slot0bits, 0, 128);
    let expiration_time = utils::from_le_bits(slot0bits, 128, 192);
    let actual_sequel = utils::from_le_bits(slot0bits, 192, 224);
    assert(actual_schema == expected_schema);
    assert(actual_sequel == expected_sequel);
    let unexpired = (expiration_time == 0) | utils::less_than(expiration_time, valid_until);
    assert(unexpired);
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


