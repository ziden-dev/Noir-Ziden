import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const rootPath = path.resolve("./src");
var circuitsPath = rootPath + '/circuits/';

function uint8ArrayToBigInt(uint8Array: Uint8Array) {
    let result = 0n;

    for (let i = 0; i < uint8Array.length; i++) {
        result <<= 8n;
        result += BigInt(uint8Array[i]);
    }

    return result;
}

function convertToHex(val: any) {
    var res;
    if (val instanceof Uint8Array) res = uint8ArrayToBigInt(val).toString(16);
    else res = BigInt(val).toString(16);
    return `"0x${'0'.repeat(64 - res.length)}${res}"`;
}

export function prove_and_verify(proof: object) {
    const formattedData = Object.entries(proof)
        .map(([key, value]) => {
            if (Array.isArray(value)) {
                return `${key}=[${value.map(val => (convertToHex(val))).join(",")}]`;
            } else {
                console.log(value)
                return `${key}=${convertToHex(value)}`;
            }
        })
        .join('\n');


    fs.writeFileSync(circuitsPath + 'Prover.toml', formattedData);

    execSync(`cd ${circuitsPath} ; nargo prove --verify`, { stdio: 'pipe' });
}

