import { SignJWT, importJWK, exportJWK } from 'jose';
import { createHash, randomUUID } from 'crypto';
import type { KeyPair } from '@inrupt/solid-client-authn-core';

/**
 * Builds a fetch function that authenticates every request with a DPoP proof.
 *
 * This replaces @inrupt's `buildAuthenticatedFetch`, whose proofs lack the
 * `ath` claim (the hash of the access token). RFC 9449 requires `ath` when a
 * DPoP proof is used alongside an access token at a resource server, and Solid
 * servers such as Community Solid Server reject proofs without it with
 * `401 invalid_dpop_proof`. The proof's `htu` is derived from the request URL
 * without its query and fragment parts, but otherwise as-is (including any
 * trailing slash, which container URLs have and servers compare strictly).
 *
 * If the server responds with a DPoP nonce challenge, the request is retried
 * once with the nonce included in the proof.
 */
export async function buildDpopAuthenticatedFetch(
  accessToken: string,
  dpopKey: KeyPair,
  underlyingFetch: typeof fetch = fetch
): Promise<typeof fetch> {
  // Support both KeyObject private keys and raw JWKs.
  let privateKey = await importJWK(await exportJWK(dpopKey.privateKey as any), 'ES256');
  let publicJwk = (({ kty, crv, x, y }: Record<string, string>) => ({ kty, crv, x, y }))(dpopKey.publicKey as unknown as Record<string, string>);
  let ath = createHash('sha256').update(accessToken).digest('base64url');

  async function createProof(htu: string, htm: string, nonce?: string): Promise<string> {
    let payload: Record<string, unknown> = {
      htu,
      htm,
      iat: Math.floor(Date.now() / 1000),
      jti: randomUUID(),
      ath,
    };
    if (nonce) payload.nonce = nonce;
    return new SignJWT(payload)
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
      .sign(privateKey);
  }

  let authenticatedFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    let requestUrl = typeof input === 'string' || input instanceof URL ? input.toString() : (input as Request).url;
    let method = (
      init?.method || (typeof input === 'object' && !(input instanceof URL) ? (input as Request).method : undefined) || 'GET'
    ).toUpperCase();

    // RFC 9449: htu is the target URI without query and fragment.
    let parsed = new URL(requestUrl);
    let htu = parsed.origin + parsed.pathname;

    let headers = new Headers(
      init?.headers ||
      (typeof input === 'object' && !(input instanceof URL) ? (input as Request).headers : undefined) ||
      undefined
    );
    headers.set('authorization', `DPoP ${accessToken}`);
    headers.set('dpop', await createProof(htu, method));

    let response = await underlyingFetch(requestUrl, { ...init, method, headers });

    // Retry once with a server-provided DPoP nonce if challenged.
    if (response.status === 401) {
      let nonce = response.headers.get('dpop-nonce');
      if (nonce) {
        headers.set('dpop', await createProof(htu, method, nonce));
        response = await underlyingFetch(requestUrl, { ...init, method, headers });
      }
    }
    return response;
  };

  return authenticatedFetch as unknown as typeof fetch;
}
