import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { convertToHexAndPad } from './bits.js';

const rootPath = path.resolve("./src");
var circuitsPath = rootPath + '/circuits/';



export function prove_and_verify(input: object) {

    const formattedData = Object.entries(input)
        .map(([key, value]) => {
            if (Array.isArray(value)) {

                return `${key}=[${value.map(val => (convertToHexAndPad(val))).join(",")}]`;
            } else {
                //console.log(value)
                return `${key}=${convertToHexAndPad(value)}`;
            }
        })
        .join('\n');


    fs.writeFileSync(circuitsPath + 'Prover.toml', formattedData);

    execSync(`cd ${circuitsPath} ; nargo prove --verify`, { stdio: 'pipe' });
}

