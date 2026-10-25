import { getSolidDataset, getThing, getUrlAll } from '@inrupt/solid-client';
import { getPodRoot } from './util';
import { getConfigCurrentWebID, getConfigStorages, setConfigStorages } from './configoptions';
import type { Logger } from '../logger';

export const PIM_STORAGE = 'http://www.w3.org/ns/pim/space#storage';

/**
 * Discover the storage root(s) (pim:storage) for a WebID by reading its profile.
 * Falls back to Link-header based pod root discovery when the profile lists none.
 */
export async function discoverStorageRoots(webId: string, fetch: Function): Promise<string[]> {
  let storages: string[] = [];
  let profileUrl = webId.split('#')[0];
  try {
    let ds = await getSolidDataset(profileUrl, { fetch: fetch as any });
    // The storage triple can live on the WebID thing or on the profile document itself.
    for (let thingUrl of [webId, profileUrl]) {
      let thing = getThing(ds, thingUrl);
      if (thing) {
        for (let storage of getUrlAll(thing, PIM_STORAGE)) {
          storages.push(storage.endsWith('/') ? storage : storage + '/');
        }
      }
    }
  } catch (_ignored) { /* profile unreadable; fall back to link header discovery */ }

  if (storages.length === 0) {
    try {
      let podRoot = await getPodRoot(webId, fetch);
      if (podRoot) storages.push(podRoot);
    } catch (_ignored) { }
  }

  // Deduplicate while preserving order.
  return [...new Set(storages)];
}

/**
 * Storage roots tracked in the config for a WebID. Discovers, verifies and
 * caches them on first use so subsequent commands do not need to re-discover.
 * Defaults to the currently set WebID.
 */
export async function getTrackedStorageRoots(webId?: string, fetch?: Function): Promise<string[] | undefined> {
  let targetWebId = webId || getConfigCurrentWebID();
  if (!targetWebId) return undefined;

  let cached = getConfigStorages(targetWebId);
  if (cached) return cached;

  if (!fetch) return undefined;
  let storages = await discoverStorageRoots(targetWebId, fetch);
  if (storages.length > 0) {
    setConfigStorages(targetWebId, storages);
    return storages;
  }
  return undefined;
}

/**
 * Expand a path that starts with `~` to the (first) tracked storage root of
 * the current WebID, mirroring shell home-directory expansion.
 */
export async function expandStoragePath(path: string, webId?: string, fetch?: Function): Promise<string> {
  if (path === '~') return (await requireFirstStorage(webId, fetch));
  if (path.startsWith('~/')) {
    let storage = await requireFirstStorage(webId, fetch);
    return storage + path.slice(2);
  }
  return path;
}

async function requireFirstStorage(webId?: string, fetch?: Function): Promise<string> {
  if (!webId && !getConfigCurrentWebID())
    throw new Error('Cannot expand "~": no WebID currently set. Authenticate first with `sld auth set <webid>`.');
  let storages = await getTrackedStorageRoots(webId, fetch);
  if (!storages || storages.length === 0)
    throw new Error('No storage root tracked for the current WebID. Run `sld auth set <webid>` to authenticate and track your pod.');
  return storages[0];
}

/**
 * Verify a session is actually alive: a locally unexpired token can still
 * have been invalidated server-side (e.g. after a server restart). Probes the
 * tracked storage root of the WebID with an authenticated HEAD request: a 401
 * there means the credentials are no longer accepted. Falls back to the IdP's
 * userinfo endpoint when no storage root is (yet) tracked.
 */
export async function isSessionTokenAlive(fetch: any, idp: string | undefined, webId?: string, logger?: Logger): Promise<boolean> {
  try {
    // Prefer probing the tracked storage root: it is the resource commands
    // operate on, and the probe result thus reflects actual access.
    let storage = (await getTrackedStorageRoots(webId, fetch))?.[0];
    if (storage) {
      let res = await fetch(storage, { method: 'HEAD' });
      if (res.status === 401) {
        logger?.log?.(`Stored session credentials were rejected for ${storage}; creating a new session.`);
        return false;
      }
      return true;
    }

    if (!idp) return true; // no IdP or storage known; cannot probe, assume alive
    // Imported lazily to avoid a circular import with authenticationUtils.
    const { getOIDCConfig } = await import('./authenticationUtils');
    let config = await getOIDCConfig(idp);
    if (!config.userinfo_endpoint) return true;
    let res = await fetch(config.userinfo_endpoint, { method: 'GET' });
    if (res.status === 401) {
      logger?.log?.(`Stored session token was rejected by ${idp}; creating a new session.`);
      return false;
    }
    return true;
  } catch (_e) {
    // Transient network failure: do not force a re-login over it.
    return true;
  }
}
