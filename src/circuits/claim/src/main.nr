use dep::noirlib;

fn main(
    claim: [Field; 8], 
    expected_schema: pub Field, 
    valid_until: pub Field, 
    expected_sequel: pub Field, 
    expected_subject: pub Field,
    eddsa_public_key_x: Field,
    eddsa_public_key_y: Field,
    eddsa_signature_s: Field,
    eddsa_signature_r8_x: Field,
    eddsa_signature_r8_y: Field,
    ecdsa_public_key_x: [u8; 32],
    ecdsa_public_key_y: [u8; 32],
    ecdsa_signature: [u8; 64],
    slot_index: pub u8,
    attesting_value: pub Field,
    operator: pub u8
    ) {
    noirlib::claim::verify_claim_fields(claim, expected_schema, valid_until, expected_sequel, expected_subject);
    let claim_hash = noirlib::claim::claim_hash(claim);
    noirlib::claim::verify_claim_eddsa_signature(claim_hash, eddsa_public_key_x, eddsa_public_key_y, eddsa_signature_s, eddsa_signature_r8_x, eddsa_signature_r8_y);
    noirlib::claim::verify_claim_ecdsa_signature(claim_hash, ecdsa_public_key_x, ecdsa_public_key_y, ecdsa_signature);
    noirlib::claim::query_single_value(claim, slot_index, attesting_value, operator);
}
