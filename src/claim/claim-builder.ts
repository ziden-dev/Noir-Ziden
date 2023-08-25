import Claim from "./claim";

export default class ClaimBuilder {
  private claim: Claim;

  constructor() {
    let slots = [];
    for (let i = 0; i < 8; i++) slots.push(Buffer.alloc(32, 0));
    this.claim = new Claim(slots);
  }

  withSlotValue(index: number, value: BigInt) {
    this.claim.setSlotValue(index, value);
  }

  withSchemaHash(schemaHash: BigInt) {
    this.claim.schemaHash = schemaHash;
  }

  withSequel(sequel: BigInt) {
    this.claim.sequel = sequel;
  }

  withExpirationTime(expirationTime: BigInt) {
    this.claim.expirationTime = expirationTime;
  }

  build(): Claim {
    return this.claim;
  }
}
