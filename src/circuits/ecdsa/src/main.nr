use dep::std;

fn main(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; 64],
    challenge: [u8; 32]
) {
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x ,public_key_y, signature, challenge) == true);
}