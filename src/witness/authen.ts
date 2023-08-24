import buildEddsa from "../crypto/eddsa.js";
import { getCurveFromName } from "../crypto/ffjavascript.js";
import { Entity } from "../state/state.js";


export async function getPublicKeyFromPrivateKey(privateKey: bigint) {
    const bn128 = await getCurveFromName('bn128', true);
    const F = bn128.Fr;
    var eddsa = await buildEddsa(F);
    const buffer = Buffer.from(privateKey.toString(16), 'hex');
    const pubkey = eddsa.prv2pub(buffer);
    return {
        publicKeyX: F.toObject(pubkey[0]),
        publicKeyY: F.toObject(pubkey[1])
    }
}

export async function signChallenge(privateKey: bigint, challenge: bigint) {
    const bn128 = await getCurveFromName('bn128', true);
    const F = bn128.Fr;
    var eddsa = await buildEddsa(F);
    const message = F.e(challenge);
    const buffer = Buffer.from(privateKey.toString(16), 'hex');
    const signature = eddsa.signPoseidon(buffer, message);
    return {
        signature_s: signature.S,
        signature_r8_x: F.toObject(signature.R8[0]),
        signature_r8_y: F.toObject(signature.R8[1]),
    }
}

export async function idOwnershipBySignature(privateKey: bigint, entity: Entity, challenge: bigint) {
    const pubkey = await getPublicKeyFromPrivateKey(privateKey);
    const signature = await signChallenge(privateKey, challenge);
    return {
        ...entity.getAuthProof(pubkey.publicKeyX),
        ...signature,
        challenge
    }
}

