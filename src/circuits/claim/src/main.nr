use dep::noirlib;

fn main(
    claim: [Field; 8], 
    expected_schema: Field, 
    valid_until: Field, 
    expected_sequel: Field, 
    expected_subject: Field,
    public_key_x: Field,
    public_key_y: Field,
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field  
    ) {
    noirlib::claim::verify_claim_fields(claim, expected_schema, valid_until, expected_sequel, expected_subject);
    let claim_hash = noirlib::claim::claim_hash(claim);
    noirlib::claim::verify_claim_eddsa_signature(claim_hash, public_key_x, public_key_y, signature_s, signature_r8_x, signature_r8_y);
}
