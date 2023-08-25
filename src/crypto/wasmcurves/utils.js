/*
    Copyright 2019 0KIMS association.

    This file is part of wasmsnark (Web Assembly zkSnark Prover).

    wasmsnark is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    wasmsnark is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with wasmsnark. If not, see <https://www.gnu.org/licenses/>.
*/
export const bigInt2BytesLE = function bigInt2BytesLE(_a, len) {
    const b = Array(len);
    let v = BigInt(_a);
    for (let i = 0; i < len; i++) {
        b[i] = Number(v & 0xFFn);
        v = v >> 8n;
    }
    return b;
};

export const bigInt2U32LE = function bigInt2BytesLE(_a, len) {
    const b = Array(len);
    let v = BigInt(_a);
    for (let i = 0; i < len; i++) {
        b[i] = Number(v & 0xFFFFFFFFn);
        v = v >> 32n;
    }
    return b;
};

export function uint8ArrayToBigInt(uint8Array) {
    let result = 0n;
    let mul2 = 1n;
    for (let i = 0; i < uint8Array.length; i++) {
        result += BigInt(uint8Array[i]) * mul2;
        mul2 <<= 8n;
    }

    return result;
}

export function bigInt2Buffer(x) {
    return Buffer.from(x.toString(16), 'hex');
}

export function buffer2BigInt(x) {
    return BigInt("0x" + x.toString('hex'));
}

export const isOcamNum = function (a) {
    if (!Array.isArray(a)) return false;
    if (a.length != 3) return false;
    if (typeof a[0] !== "number") return false;
    if (typeof a[1] !== "number") return false;
    if (!Array.isArray(a[2])) return false;
    return true;
};

