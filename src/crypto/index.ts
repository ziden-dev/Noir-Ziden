import buildEddsa from "./eddsa.js";
import { getCurveFromName } from "./ffjavascript.js";
import { buildPoseidon } from "./poseidon_wasm.js";

export class CryptographyPrimitives {
  bn128: any;
  bn128ScalarField: any;
  poseidon: any;
  eddsa: any;
  private static instance: CryptographyPrimitives;
  private constructor() {}
  private async initialize() {
    this.bn128 = await getCurveFromName("bn128", true);
    this.bn128ScalarField = this.bn128.Fr;
    this.poseidon = await buildPoseidon();
    this.eddsa = await buildEddsa(this.bn128ScalarField);
  }
  public static async getInstance(): Promise<CryptographyPrimitives> {
    if (!CryptographyPrimitives.instance) {
      CryptographyPrimitives.instance = new CryptographyPrimitives();
      await CryptographyPrimitives.instance.initialize();
    }

    return CryptographyPrimitives.instance;
  }
}
