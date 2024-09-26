use dep::noirlib;
fn main(
    claim: [Field; 8],

    // Id ownership proof - IOP
    public_key_x: Field,
    public_key_y: Field,
    iop_auth_path: [Field; 3],
    iop_auth_index: Field,
    iop_claim_root: Field,
    iop_revoked_claim_root: Field,
    holder_state: pub Field,
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    challenge: pub Field,
    
    // Claim existence proof - CEP
    cep_claim_merkle_path: [Field; 3], 
    cep_claim_index: Field, 
    cep_claim_root: Field,
    cep_auth_root: Field,
    cep_revoked_claim_root: Field,
    cep_issuer_state: pub Field,

    // Claim non-revocation proof - CNP
    cnp_path_low: [Field; 3], 
    cnp_val_low: Field, 
    cnp_next_val: Field, 
    cnp_next_idx: Field, 
    cnp_index_low: Field, 
    cnp_revocation_root: Field,
    cnp_auth_root: Field,
    cnp_claim_root: Field,
    cnp_issuer_state: pub Field,

    // Claim validation
    expected_schema: pub Field, 
    valid_until: pub Field, 
    expected_sequel: pub Field, 
    expected_subject: pub Field,

    /*
    0: single
    1: double
    2: set
    3: non-set
    */
    query_type: pub u8, 
    // Claim query
    slot_index_0: pub u8,
    slot_index_1: pub u8, 
    attesting_value: pub Field, 
    operator: pub u8,

    // Set membership
    set_root: pub Field, 
    set_index: Field, 
    set_merkle_proof: [Field; 2],

    // Set non-membership - SNM
    snm_path_low: [Field; 2], 
    snm_val_low: Field, 
    snm_next_val: Field, 
    snm_next_idx: Field, 
    snm_index_low: Field, 
    snm_root: pub Field
) {
    noirlib::claim_presentation::present_claim_with_eddsa(
        claim,

        // Id ownership proof - IOP
        public_key_x,
        public_key_y,
        iop_auth_path,
        iop_auth_index,
        iop_claim_root,
        iop_revoked_claim_root,
        holder_state,
        signature_s,
        signature_r8_x,
        signature_r8_y,
        challenge,
    
        // Claim existence proof - CEP
        cep_claim_merkle_path, 
        cep_claim_index, 
        cep_claim_root,
        cep_auth_root,
        cep_revoked_claim_root,
        cep_issuer_state,

        // Claim non-revocation proof - CNP
        cnp_path_low, 
        cnp_val_low, 
        cnp_next_val, 
        cnp_next_idx, 
        cnp_index_low, 
        cnp_revocation_root,
        cnp_auth_root,
        cnp_claim_root,
        cnp_issuer_state,

        // Claim validation
        expected_schema, 
        valid_until, 
        expected_sequel, 
        expected_subject,

        query_type, 
        // Claim query
        slot_index_0,
        slot_index_1, 
        attesting_value, 
        operator,

        // Set membership
        set_root, 
        set_index, 
        set_merkle_proof,

        // Set non-membership - SNM
        snm_path_low, 
        snm_val_low, 
        snm_next_val, 
        snm_next_idx, 
        snm_index_low, 
        snm_root
    );
}
