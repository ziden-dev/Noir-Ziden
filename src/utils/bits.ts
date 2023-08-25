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

