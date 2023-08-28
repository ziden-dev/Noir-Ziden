import Claim from "./claim.js";

export default class ClaimBuilder {
  private claim: Claim;

  constructor() {
    let slots = [];
    for (let i = 0; i < 8; i++) slots.push(Buffer.alloc(32, 0));
    this.claim = new Claim(slots);
  }

  withSlotValue(index: number, value: BigInt) {
    this.claim.setSlotValue(index, value);
    return this;
  }

  withSchemaHash(schemaHash: BigInt) {
    this.claim.schemaHash = schemaHash;
    return this;
  }

  withSequel(sequel: BigInt) {
    this.claim.sequel = sequel;
    return this;
  }

  withExpirationTime(expirationTime: BigInt) {
    this.claim.expirationTime = expirationTime;
    return this;
  }

  withSubject(subject: BigInt) {
    this.claim.subject = subject;
    return this;
  }

  build(): Claim {
    return this.claim;
  }
}
