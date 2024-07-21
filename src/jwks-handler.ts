import jose, { JWK, importJWK, exportSPKI } from "jose";
import jwkToPem from "jwk-to-pem";

export class JwksHandler {
  private jwksUri: string;

  constructor(jwksUri: string) {
    this.jwksUri = jwksUri;
  }

  public async getCryptoKey(jwk: JWK, alg?: string): Promise<CryptoKey> {
    return (await importJWK(jwk, alg)) as CryptoKey;
  }

  // Optional: Method to get public key in PEM format
  getPublicKeyPEM(key: { kid: string } & any): string {
    try {
      return jwkToPem(key);
    } catch (error) {
      throw error;
    }
  }
}

// Usage
