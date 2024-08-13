// https://k94n.com/es6-modules-single-instance-pattern
import JsonWebToken, { JwtHeader, SigningKeyCallback } from "jsonwebtoken";
import jwksClient from "jwks-rsa";

export class JWTHandler<T> {
  protected client: jwksClient.JwksClient;

  public constructor(jwksUri: string) {
    this.client = jwksClient({ jwksUri });
  }

  getKey(header: JwtHeader, callback: SigningKeyCallback) {
    this.client.getSigningKey(header.kid, function (err, key) {
      const signingKey = key!.getPublicKey();
      callback(err, signingKey);
    });
  }

  public convertDaysToSeconds(days: number): number {
    const secondsInADay = 86400;
    return days * secondsInADay;
  }

  /**
   * Decodes a JSON Web Token (JWT) using the provided key.
   *
   * @param {string} jwt - The JWT to decode.
   * @return {Promise<[any, boolean]>} A Promise that resolves to an array containing the decoded JWT and a boolean indicating success.
   * If the decoding fails, the Promise is rejected with the error.
   */
  public async decodeJWT(jwt: string): Promise<[T & JsonWebToken.JwtPayload, boolean]> {
    const self = this;

    return new Promise((resolve) => {
      JsonWebToken.verify(
        jwt,
        (header, callback) => self.getKey(header, callback),
        {},
        function (err, decoded) {
          let decodedJWT = decoded;
          // Use JWT
          if (err) {
            [undefined, false];
          }

          resolve([decodedJWT as T & JsonWebToken.JwtPayload, true]);
        }
      );
    });
  }
}
