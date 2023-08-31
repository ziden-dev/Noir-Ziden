use dep::std;
mod claim;
mod id_ownership_by_signature;
mod state;
mod utils;

fn present_claim_with_eddsa<AuthDepth, ClaimDepth, SetDepth>(
    claim: [Field; 8],

    // Id ownership proof - IOP
    public_key_x: Field,
    public_key_y: Field,
    iop_auth_path: [Field; AuthDepth],
    iop_auth_index: Field,
    iop_claim_root: Field,
    iop_revoked_claim_root: Field,
    holder_state: Field,
    signature_s: Field,
    signature_r8_x: Field,
    signature_r8_y: Field,
    challenge: Field,
    
    // Claim existence proof - CEP
    cep_claim_merkle_path: [Field; ClaimDepth], 
    cep_claim_index: Field, 
    cep_claim_root: Field,
    cep_auth_root: Field,
    cep_revoked_claim_root: Field,
    cep_issuer_state: Field,

    // Claim non-revocation proof - CNP
    cnp_path_low: [Field; ClaimDepth], 
    cnp_val_low: Field, 
    cnp_next_val: Field, 
    cnp_next_idx: Field, 
    cnp_index_low: Field, 
    cnp_revocation_root: Field,
    cnp_auth_root: Field,
    cnp_claim_root: Field,
    cnp_issuer_state: Field,

    // Claim validation
    expected_schema: Field, 
    valid_until: Field, 
    expected_sequel: Field, 
    expected_subject: Field,

    /*
    0: single
    1: double
    2: set
    3: non-set
    */
    query_type: u8, 
    // Claim query
    slot_index_0: u8,
    slot_index_1: u8, 
    attesting_value: Field, 
    operator: u8,

    // Set membership
    set_root: Field, 
    set_index: Field, 
    set_merkle_proof: [Field; SetDepth],

    // Set non-membership - SNM
    snm_path_low: [Field; SetDepth], 
    snm_val_low: Field, 
    snm_next_val: Field, 
    snm_next_idx: Field, 
    snm_index_low: Field, 
    snm_root: Field
){


    id_ownership_by_signature::eddsa_ownership_verify(
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
        challenge
    );

    let claim_hash = claim::claim_hash(claim);

    state::check_claim_existence(claim_hash, cep_claim_merkle_path, cep_claim_index, cep_claim_root);
    state::check_identity_state(cep_auth_root, cep_claim_root, cep_revoked_claim_root, cep_issuer_state);

    state::check_claim_nonrevocation(
        claim_hash, 
        cnp_path_low, 
        cnp_val_low, 
        cnp_next_val, 
        cnp_next_idx, 
        cnp_index_low, 
        cnp_revocation_root
    );
    state::check_identity_state(cnp_auth_root, cnp_claim_root, cnp_revocation_root, cnp_issuer_state);

    claim::verify_claim_fields(
        claim, 
        expected_schema, 
        valid_until, 
        expected_sequel, 
        expected_subject
    );

    if(query_type == 0){
        claim::query_single_value(
            claim,
            slot_index_0,
            attesting_value,
            operator
        );
    } else if (query_type == 1) {
        claim::query_double_values(
            claim,
            slot_index_0,
            slot_index_1,
            operator
        );
    } else if(query_type == 2) {
        claim::verify_membership(
            claim,
            slot_index_0,
            set_root, 
            set_index, 
            set_merkle_proof,
        );
    } else if(query_type == 3) {
        claim::verify_non_membership(
            claim,
            slot_index_0,
            snm_path_low, 
            snm_val_low, 
            snm_next_val, 
            snm_next_idx, 
            snm_index_low, 
            snm_root
        );
    }

}
fn present_claim_with_ecdsa<AuthDepth, ClaimDepth, SetDepth>(
    claim: [Field; 8],

    // Id ownership proof - IOP
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    iop_auth_path: [Field; AuthDepth],
    iop_auth_index: Field,
    iop_claim_root: Field,
    iop_revoked_claim_root: Field,
    holder_state: Field,
    signature: [u8; 64],
    challenge: Field,
    
    // Claim existence proof - CEP
    cep_claim_merkle_path: [Field; ClaimDepth], 
    cep_claim_index: Field, 
    cep_claim_root: Field,
    cep_auth_root: Field,
    cep_revoked_claim_root: Field,
    cep_issuer_state: Field,

    // Claim non-revocation proof - CNP
    cnp_path_low: [Field; ClaimDepth], 
    cnp_val_low: Field, 
    cnp_next_val: Field, 
    cnp_next_idx: Field, 
    cnp_index_low: Field, 
    cnp_revocation_root: Field,
    cnp_auth_root: Field,
    cnp_claim_root: Field,
    cnp_issuer_state: Field,

    // Claim validation
    expected_schema: Field, 
    valid_until: Field, 
    expected_sequel: Field, 
    expected_subject: Field,

    /*
    0: single
    1: double
    2: set
    3: non-set
    */
    query_type: u8, 
    // Claim query
    slot_index_0: u8,
    slot_index_1: u8, 
    attesting_value: Field, 
    operator: u8,

    // Set membership
    set_root: Field, 
    set_index: Field, 
    set_merkle_proof: [Field; SetDepth],

    // Set non-membership - SNM
    snm_path_low: [Field; SetDepth], 
    snm_val_low: Field, 
    snm_next_val: Field, 
    snm_next_idx: Field, 
    snm_index_low: Field, 
    snm_root: Field

){
    id_ownership_by_signature::ecdsa_ownership_verify(
        public_key_x,
        public_key_y,
        iop_auth_path,
        iop_auth_index,
        iop_claim_root,
        iop_revoked_claim_root,
        holder_state,
        signature,
        challenge
    );

    let claim_hash = claim::claim_hash(claim);

    state::check_claim_existence(claim_hash, cep_claim_merkle_path, cep_claim_index, cep_claim_root);
    state::check_identity_state(cep_auth_root, cep_claim_root, cep_revoked_claim_root, cep_issuer_state);

    state::check_claim_nonrevocation(
        claim_hash, 
        cnp_path_low, 
        cnp_val_low, 
        cnp_next_val, 
        cnp_next_idx, 
        cnp_index_low, 
        cnp_revocation_root
    );
    state::check_identity_state(cnp_auth_root, cnp_claim_root, cnp_revocation_root, cnp_issuer_state);

    claim::verify_claim_fields(
        claim, 
        expected_schema, 
        valid_until, 
        expected_sequel, 
        expected_subject
    );

if(query_type == 0){
        claim::query_single_value(
            claim,
            slot_index_0,
            attesting_value,
            operator
        );
    } else if (query_type == 1) {
        claim::query_double_values(
            claim,
            slot_index_0,
            slot_index_1,
            operator
        );
    } else if(query_type == 2) {
        claim::verify_membership(
            claim,
            slot_index_0,
            set_root, 
            set_index, 
            set_merkle_proof,
        );
    } else if(query_type == 3) {
        claim::verify_non_membership(
            claim,
            slot_index_0,
            snm_path_low, 
            snm_val_low, 
            snm_next_val, 
            snm_next_idx, 
            snm_index_low, 
            snm_root
        );
    }
}