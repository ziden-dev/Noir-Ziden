import { decompressSync } from "fflate";
import { newBarretenbergApiAsync } from "@aztec/bb.js/dest/node/index.js";
import * as fs from 'fs';


import ecdsaClaimPresentationCircuit from "./circuits/ecdsa_claim_presentation/target/ecdsa_claim_presentation.json" assert { type: "json" };
import eddsaClaimPresentationCircuit from "./circuits/eddsa_claim_presentation/target/eddsa_claim_presentation.json" assert { type: "json" };
import ecdsaStateTransitionCircuit from "./circuits/ecdsa_state_transition/target/ecdsa_state_transition.json" assert { type: "json" };
import eddsaStateTransitionCircuit from "./circuits/eddsa_state_transition/target/eddsa_state_transition.json" assert { type: "json" };


let api: any;

async function getCircuitSize(circuit: any) {
    var acirBuffer = Buffer.from(circuit.bytecode, "base64");
    var acirBufferUncompressed = decompressSync(acirBuffer);

    const [_exact, circuitSize, _subgroup] = await api.acirGetCircuitSizes(
        acirBufferUncompressed
    );
    return circuitSize;
}
async function main() {
    api = await newBarretenbergApiAsync(4);
    var data = `ecdsa claim presentation circuit size: ${await getCircuitSize(ecdsaClaimPresentationCircuit)}\n`;
    data = data + (`eddsa claim presentation circuit size: ${await getCircuitSize(eddsaClaimPresentationCircuit)}\n`);
    data = data + (`ecdsa state transition circuit size: ${await getCircuitSize(ecdsaStateTransitionCircuit)}\n`);
    data = data + (`eddsa state transition circuit size: ${await getCircuitSize(eddsaStateTransitionCircuit)}\n`);

    fs.writeFileSync("benchmark-constraints.txt", data)
}

main()
    .then(e => {
        console.log("OK");
    })
    .catch(e => {
        console.log(e)
    });