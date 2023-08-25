import { CryptographyPrimitives } from "src/crypto";
import { bitsToNum, numToBits } from "src/utils/bits";

export default class Claim {
  private slots: Array<Buffer>;

  constructor(slots: Array<Buffer>) {
    if (slots.length !== 8) throw new Error("the claim must have 8 slots");
    this.slots = slots;
  }

  get schemaHash() {
    let schemaHash = Buffer.alloc(16, 0);
    this.slots[0].copy(schemaHash);
    return bitsToNum(schemaHash);
  }

  get sequel() {
    let sequelBits = Buffer.alloc(4, 0);
    this.slots[0].copy(sequelBits, 0, 24, 28);
    return bitsToNum(sequelBits);
  }

  get expirationTime() {
    let expireBits = Buffer.alloc(8, 0);
    this.slots[0].copy(expireBits, 0, 16, 24);
    return bitsToNum(expireBits);
  }

  async claimHash() {
    const crypto = await CryptographyPrimitives.getInstance();
    const hashBits = crypto.poseidon(this.slots.map((e) => bitsToNum(e)));
    return crypto.bn128ScalarField.toObject(hashBits);
  }

  async eddsaSign(privateKey: Buffer) {
    const crypto = await CryptographyPrimitives.getInstance();
    const msg = crypto.poseidon(this.slots.map((e) => bitsToNum(e)));
    return crypto.eddsa.signPoseidon(privateKey, msg);
  }

  getSlotValue(index: number) {
    if (index < 0 || index > 7)
      throw new Error("the index must be from 0 to 7");
    return bitsToNum(this.slots[index]);
  }

  set schemaHash(schemaHash: BigInt) {
    let schemaHashBits = numToBits(schemaHash, 16);
    schemaHashBits.copy(this.slots[0]);
  }

  set sequel(sequel: BigInt) {
    let sequelBits = numToBits(sequel, 4);
    sequelBits.copy(this.slots[0], 24);
  }

  set expirationTime(expirationTime: BigInt) {
    let expireBits = numToBits(expirationTime, 8);
    expireBits.copy(this.slots[0], 16);
  }

  setSlotValue(index: number, value: BigInt) {
    if (index < 0 || index > 7)
      throw new Error("the index must be from 0 to 7");
    let valueBits = numToBits(value, 32);
    valueBits.copy(this.slots[index]);
  }
}
