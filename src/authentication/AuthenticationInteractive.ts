import { getOIDCConfig, getSessionInfoFromStorage, StorageHandler, OIDCConfig, readSessionTokenInfo, storeSessionTokenInfo, decodeIdToken, writeErrorString } from '../utils/authenticationUtils';
import { isSessionTokenAlive } from '../utils/storages';
import { generateDpopKeyPair, KeyPair, createDpopHeader } from '@inrupt/solid-client-authn-core';
import { buildDpopAuthenticatedFetch } from '../utils/dpopFetch';
import formurlencoded from 'form-urlencoded';
import { Session } from '@inrupt/solid-client-authn-node';
import open from 'open';
import { removeConfigSession, getConfigCurrentSession, getConfigCurrentWebID, ISessionEntry, setConfigCurrentWebID, setConfigSession } from '../utils/configoptions';
import chalk from 'chalk';
import { getUserIdp } from './authenticate';
import BashlibError from '../utils/errors/BashlibError';
import { BashlibErrorMessage } from '../utils/errors/BashlibError';
import crossfetch from 'cross-fetch';

import express from 'express';
import { Logger } from '../logger';

export interface SessionInfo {
  fetch: typeof fetch
  webId?: string
}

export interface IInteractiveAuthOptions {
  idp?: string,
  sessionInfoStorageLocation?: string, // Storage location of session information to reuse in subsequent runs of the application.
  port?: number, // Used for redirect url of Solid login sequence
  verbose?: boolean,
  logger?: Logger,
}

export const DEFAULTPORT = 3435
export const APPNAME = "Solid-cli"

export default async function authenticateInteractive(options: IInteractiveAuthOptions) : Promise<SessionInfo> {

  let appName = APPNAME
  let port = options.port || DEFAULTPORT

  let currentSession = getConfigCurrentSession();
  try {
    if (currentSession) {
      let sessionInfo = await readSessionTokenInfo();
      if (options.idp && (!sessionInfo.idp || sessionInfo.idp !== options.idp))
        throw new BashlibError(BashlibErrorMessage.cannotRestoreSession)
      if (sessionInfo) {
        var tokenTimeLeftInSeconds = (sessionInfo.expirationDate.getTime() - new Date().getTime()) / 1000;
        if (tokenTimeLeftInSeconds > 60) {
          // Only reuse previous session tokens if we have enough time to work with, else continue to create a new access token.
          let fetch = await buildDpopAuthenticatedFetch(sessionInfo.accessToken, sessionInfo.dpopKey);
          // Verify the stored token is still accepted by the IdP; a locally
          // unexpired token can still have been invalidated server-side.
          if (await isSessionTokenAlive(fetch, sessionInfo.idp, sessionInfo.webId, options.logger)) {
            let webId = sessionInfo.webId;
            return { fetch, webId }
          }
          // Stale token: drop the stored session and create a new one.
          let staleWebId = getConfigCurrentWebID();
          if (staleWebId) { removeConfigSession(staleWebId) }
        } else { 
          // remove timed out session
          let webId = getConfigCurrentWebID();
          if (webId) { removeConfigSession(webId) }
        }
      }
    }
  } catch (e) {
    if (options?.verbose) writeErrorString('Could not load existing session', e, options);
  }


  // Check for available IDP. If not, require one from the user.
  if (!options.idp) { 
    if (currentSession && currentSession.idp) {
      if (process.stdin.isTTY) {
        console.log(`Continue authenticating with ${chalk.bold(currentSession.idp)} ? [Y/n] `);
        options.idp = await new Promise((resolve, reject) => {
          process.stdin.setRawMode(true);
          process.stdin.resume();
          process.stdin.on('data', (chk) => {
            if (chk.toString('utf8') === "n") {
              resolve(undefined);
            } else {
              resolve((currentSession as ISessionEntry).idp);
            }
          });
        });
      } else {
        // Without a terminal there is nobody to answer: continue with the known IdP.
        console.log(`Continuing with ${chalk.bold(currentSession.idp)}.`);
        options.idp = currentSession.idp;
      }
    }
  }

  if (!options.idp) { options.idp = await getUserIdp() }
  if (!options.idp) throw new BashlibError(BashlibErrorMessage.noIDPOption)

  try {
    return await createFetchWithNewAccessToken(options.idp, appName, port)
  } catch (e) {
    // The user went through a browser login; never hide why it failed.
    writeErrorString('Error creating new session', e, options);
    throw e
  }
  

}

/**
 * Handle login flow if no existing session can be reused
 * @param oidcIssuer 
 * @param appName 
 * @param port 
 * @param storageLocation 
 * @returns 
 */
async function createFetchWithNewAccessToken(oidcIssuer: string, appName: string, port: number) : Promise<SessionInfo> {
  return new Promise( async (resolve, reject) => {
    let config;
    try {
      config = await getOIDCConfig(oidcIssuer);
    } catch (e) {
      return reject(e)
    }
    if (!config) return reject(new Error("Could not read oidc config"));

    const app = express();
    const redirectUrl = `http://localhost:${port}/`;
    const storage = new StorageHandler();
    
    let session : Session = new Session({
      insecureStorage: storage,
      secureStorage: storage,
    });
    const handleRedirect = (url: string) => { open(url) }

    const server = app.listen(port, async () => {  
      const loginOptions = {
        clientName: appName,
        oidcIssuer,
        redirectUrl,
        tokenType: "DPoP" as "DPoP", // typescript fix
        handleRedirect,
      };
      try {
        await session.login(loginOptions)
      } catch (e) {
        server.close();
        reject (e)
      }
    });

    // Without this, a port conflict (e.g. a leftover process from a previous
    // login attempt) crashes the process with an unhandled 'error' event.
    server.on('error', (e: Error) => {
      reject(new Error(`Could not listen on port ${port} for the authentication redirect: ${e.message}`))
    });
    
    app.get("/", async (_req: any, res: any) => {
      try {
        const code = new URL(_req.url, redirectUrl).searchParams.get('code');
        if (!code) throw new BashlibError(BashlibErrorMessage.authFlowError, undefined, 'Server did not return code.')
        let { accessToken, expirationDate, dpopKey, webId } = await handleIncomingRedirect(oidcIssuer, redirectUrl, code, storage)
        
        // Store the session info
        await storeSessionTokenInfo(accessToken, dpopKey, expirationDate, webId, oidcIssuer)
        let fetch = await buildDpopAuthenticatedFetch(accessToken, dpopKey);

        // Set the current WebID to the current session
        await setConfigCurrentWebID(webId)

        // Always answer the browser: otherwise the request hangs until this
        // process exits, which browsers report as "Unable to connect".
        res.status(200).send('Authentication successful. You can close this window and return to the terminal.')
        server.close();
        resolve({
          fetch, webId
        })
      } catch (e) {
        let message = (e instanceof Error) ? e.message : String(e);
        res.status(500).send(`Authentication failed: ${message} You can close this window and return to the terminal.`)
        server.close();
        reject(new Error(`Error authenticating with received token: ${message}`))
      }
    });
  })
}



/**
 * Handles incoming redirect request and returns relevant access token info extracted.
 * @param idp 
 * @param redirectUrl 
 * @param code 
 * @param storage 
 * @returns 
 */
export async function handleIncomingRedirect(idp: string, redirectUrl: string, code: string, storage: StorageHandler) {
  let config = await getOIDCConfig(idp)
  let dpopKey = await generateDpopKeyPair();
  let sessionInfo = await getSessionInfoFromStorage(storage);
  // clientSecret is absent for public clients (IdPs registering with
  // token_endpoint_auth_method "none"); those authenticate through PKCE only.
  if (!sessionInfo || !sessionInfo.clientId || !(sessionInfo as any).codeVerifier)
    throw new BashlibError(BashlibErrorMessage.cannotCreateSession)

  return await requestAccessToken({
    dpopKey,
    code,
    codeVerifier: (sessionInfo as any).codeVerifier,
    clientId: sessionInfo.clientId,
    clientSecret: sessionInfo.clientSecret,
    redirectUrl,
    config,
  })

}


async function requestAccessToken(p: {
      dpopKey: KeyPair, 
      code: string, 
      codeVerifier: string, 
      clientId: string, 
      clientSecret?: string, 
      redirectUrl: string
      config: OIDCConfig
    }) : Promise<{ accessToken: string, expirationDate: Date, dpopKey: KeyPair, webId: string }>
  {

    // Public clients (no client secret) authenticate through PKCE
    // (client_id + code_verifier in the body) and must not send an
    // Authorization header: some IdPs reject the request outright if they do.
    const headers: Record<string, string> = {
      'content-type': 'application/x-www-form-urlencoded',
      dpop: await createDpopHeader(p.config.token_endpoint, 'POST', p.dpopKey),
    };
    if (p.clientSecret) {
      const authString = `${encodeURIComponent(p.clientId)}:${encodeURIComponent(p.clientSecret)}`;
      headers['authorization'] = `Basic ${Buffer.from(authString).toString('base64')}`;
    }

    const response = await fetch(p.config.token_endpoint, {
      method: 'POST',
      headers,
      body: formurlencoded({
        grant_type: 'authorization_code',
        redirect_uri: p.redirectUrl,
        code: p.code,
        code_verifier: p.codeVerifier,
        client_id: p.clientId,
      }),
    });

  let json = await response.json()
  if (json.error) {
    throw new BashlibError(BashlibErrorMessage.authFlowError, undefined, json.error)
  }

  let accessToken = json.access_token;
  let tokenExpiratationInSeconds = json.expires_in;

  let currentDate = new Date();
  let expirationDate = new Date(currentDate.getTime() + (1000 * tokenExpiratationInSeconds))

  let idTokenInfo = decodeIdToken(json.id_token);
  let webId = idTokenInfo.webid || idTokenInfo.sub;
  if (!idTokenInfo || !webId) 
    throw new BashlibError(BashlibErrorMessage.authFlowError, undefined, 'Cannot retrieve webid from id token.')

  return { accessToken, expirationDate, dpopKey: p.dpopKey, webId };
}
