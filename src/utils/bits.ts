import { toBigIntBE, toBufferBE } from "bigint-buffer";
/**
 * Allocates a new Buffer from a bigInt number in little-endian format
 * @category utils
 * @param {bigInt} number - bigInt number
 * @returns {Buffer} - Decoded Buffer
 */
export function numToBits(number: BigInt, width: number): Buffer {
  const buff = toBufferBE(number.valueOf(), width);
  return swapEndianness(buff);
}

/**
 * Allocates a new bigInt from a buffer in big-endian format
 * @category utils
 * @param {Buffer} buff - Buffer to convert
 * @returns {BigInt} - Decoded bigInt
 */
export function bitsToNum(buff: Buffer): BigInt {
  const revBuff = swapEndianness(buff);
  return toBigIntBE(revBuff);
}
/**
 * Swap endianess buffer from big endian to little endian and vice versa
 * @category utils
 * @param {Buffer} buff - Buffer to swap
 * @returns {Buffer} - Buffer swapped
 */
export function swapEndianness(buff: Buffer): Buffer {
  const len = buff.length;
  let buffSwap = Buffer.alloc(len);
  for (let i = 0; i < len; i++) {
    buffSwap[i] = 0;
    for (let j = 0; j < 8; j++) {
      const bit = (buff[len - 1 - i] & (1 << j)) > 0;
      if (bit) {
        buffSwap[i] |= 1 << (7 - j);
      }
    }
  }
  return buffSwap;
}

/**
 * Convert buffer to hex string
 * @category utils
 * @param {Buffer} buff
 * @returns {string}
 */
export function bufferToHex(buff: Buffer): string {
  return bitsToNum(buff).toString(16);
}

export function convertToHexAndPad(val: any) {
  var res;
  if (val instanceof Uint8Array) res = uint8ArrayToBigInt(val).toString(16);
  else res = BigInt(val).toString(16);
  return `0x${"0".repeat(64 - res.length)}${res}`;
}

export function bigInt2BytesLE(_a: any, len: number) {
  const b = Array(len);
  let v = BigInt(_a);
  for (let i = 0; i < len; i++) {
    b[i] = Number(v & 0xffn);
    v = v >> 8n;
  }
  return b;
}

export function uint8ArrayToBigInt(uint8Array: Uint8Array): BigInt {
  let result = 0n;
  let mul2 = 1n;
  for (let i = 0; i < uint8Array.length; i++) {
    result += BigInt(uint8Array[i]) * mul2;
    mul2 <<= 8n;
  }

  return result;
}

export function bigInt2Uint8Array(value: BigInt, length: number) {
  const hexString = value.toString(16);
  if (hexString.length > length * 2) {
    return new Uint8Array(length);
  }
  const paddedHexString = hexString.padStart(length * 2, "0");
  const byteArray = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    byteArray[length - i - 1] = parseInt(paddedHexString.substr(i * 2, 2), 16);
  }
  return byteArray;
}

export function object2Array(object: any) {
  var res: any[] = [];
  for (const [_key, value] of Object.entries(object)) {
    if (Array.isArray(value)) res = res.concat(...value);
    else res.push(value);
  }
  return res;
}

export function flattenObject(obj: any): any[] {
  const result: any[] = [];

  function traverse(innerObj: any): void {
    for (const key in innerObj) {
      if (innerObj.hasOwnProperty(key)) {
        const value = innerObj[key];

        if (typeof value === 'object') {
          if (Array.isArray(value)) {
            result.push(...value);
          } else {
            traverse(value);
          }
        } else {
          result.push(value);
        }
      }
    }
  }

  traverse(obj);
  return result;
}