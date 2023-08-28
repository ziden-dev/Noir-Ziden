export interface EDDSAPublicKey {
  X: BigInt;
  Y: BigInt;
}

export interface ECDSAPublicKey {
  X: BigInt;
  Y: BigInt;
}

export interface ECDSAPublickeyLEBytes {
  X: number[];
  Y: number[];
}

export interface EDDSASignature {
  R8X: BigInt;
  R8Y: BigInt;
  S: BigInt;
}

export type ECDSASignature = number[];
