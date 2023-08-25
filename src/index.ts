export interface EDDSAPublicKey {
  X: BigInt;
  Y: BigInt;
}

export interface EDDSASignature {
  R8: Array<ArrayLike<number>>;
  S: BigInt;
}
