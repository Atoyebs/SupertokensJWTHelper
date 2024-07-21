import jose, { createRemoteJWKSet, JWK, importJWK, exportSPKI } from "jose";

export class JwksHandler {
  private jwksUri: string;

  constructor(jwksUri: string) {
    this.jwksUri = jwksUri;
  }

  private async fetchJWKS(): Promise<{ keys: JWK[] }> {
    const response = await fetch(this.jwksUri);
    if (!response.ok) {
      throw new Error(`Failed to fetch JWKS: ${response.statusText}`);
    }
    return response.json();
  }

  // Optional: Method to get public key in PEM format
  async getPublicKeyPEM(key: { kid: string } & any, kid: string): Promise<string> {
    if (!key) {
      throw new Error(`No key found with kid: ${kid}`);
    }

    const publicKey = (await importJWK(key, key.alg)) as jose.KeyLike;
    const publicKeyPEM = await exportSPKI(publicKey);
    return publicKeyPEM;
  }
}

// Usage
