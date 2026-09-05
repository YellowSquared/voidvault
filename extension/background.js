/**
 * VoidVault Minimal Background Service
 * In-memory vault management, auto-lock zeroing, and blind server synchronization.
 */

(function () {
  'use strict';

  const extAPI = typeof browser !== 'undefined' ? browser : chrome;
  const DEFAULT_SERVER_BASE = 'http://localhost:8080';
  const AUTO_LOCK_MS = 15 * 60 * 1000; // 15 minutes

  function normalizeUrl(url) {
    if (!url) return DEFAULT_SERVER_BASE;
    let clean = url.trim();
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
      clean = 'http://' + clean;
    }
    return clean.replace(/\/+$/, '');
  }

  async function getServerBase() {
    try {
      const stored = await extAPI.storage.local.get(['serverUrl']);
      if (stored && stored.serverUrl) {
        return normalizeUrl(stored.serverUrl);
      }
    } catch {}
    return DEFAULT_SERVER_BASE;
  }

  let isUnlocked = false;
  let activeAesKey = null;
  let activePrfOutput = null;
  let inMemoryVault = null;
  let autoLockTimerId = null;
  let syncVersion = 1;
  let serverConnected = false;

  function resetAutoLockTimer() {
    if (autoLockTimerId) {
      clearTimeout(autoLockTimerId);
    }
    if (isUnlocked) {
      autoLockTimerId = setTimeout(() => {
        lockVault();
      }, AUTO_LOCK_MS);
    }
  }

  function lockVault() {
    if (activePrfOutput) {
      VoidVaultCrypto.zeroBuffer(activePrfOutput);
      activePrfOutput = null;
    }
    if (inMemoryVault) {
      inMemoryVault.length = 0;
      inMemoryVault = null;
    }
    activeAesKey = null;
    isUnlocked = false;
    if (autoLockTimerId) {
      clearTimeout(autoLockTimerId);
      autoLockTimerId = null;
    }
    console.log('[VoidVault Minimal] Vault locked, volatile memory scrubbed.');
  }

  async function getLocator(credentialId) {
    let id = credentialId;
    if (!id) {
      const stored = await extAPI.storage.local.get(['credentialId']);
      id = stored.credentialId || 'default-user';
    }
    const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(id));
    return VoidVaultCrypto.bufferToHex(hashBuf);
  }

  async function pushToServer(encryptedCapsule, version, credentialId) {
    try {
      const serverBase = await getServerBase();
      const locator = await getLocator(credentialId);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);

      const res = await fetch(`${serverBase}/api/vault/${locator}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          version: version,
          capsule: encryptedCapsule
        }),
        signal: controller.signal
      }).catch(() => null);

      clearTimeout(timeout);
      if (res && res.ok) {
        serverConnected = true;
        return true;
      }
    } catch {
      serverConnected = false;
    }
    return false;
  }

  async function pullFromServer(credentialId) {
    try {
      const serverBase = await getServerBase();
      const locator = await getLocator(credentialId);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);

      const res = await fetch(`${serverBase}/api/vault/${locator}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        signal: controller.signal
      }).catch(() => null);

      clearTimeout(timeout);
      if (res && res.ok) {
        serverConnected = true;
        const data = await res.json();
        return data?.capsule || null;
      }
    } catch {
      serverConnected = false;
    }
    return null;
  }

  async function checkServerHealth(targetUrl = null) {
    try {
      const serverBase = targetUrl ? normalizeUrl(targetUrl) : await getServerBase();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 1500);
      const res = await fetch(`${serverBase}/health`, { signal: controller.signal }).catch(() => null);
      clearTimeout(timeout);
      const ok = Boolean(res && res.ok);
      if (!targetUrl) {
        serverConnected = ok;
      }
      return ok;
    } catch {
      if (!targetUrl) {
        serverConnected = false;
      }
      return false;
    }
  }

  // Periodic health check
  checkServerHealth();
  setInterval(checkServerHealth, 20000);

  extAPI.runtime.onMessage.addListener((message, sender, sendResponse) => {
    (async () => {
      try {
        switch (message?.action) {
          case 'GET_STATUS': {
            resetAutoLockTimer();
            await checkServerHealth();
            const serverBase = await getServerBase();
            return {
              isUnlocked,
              syncVersion,
              serverConnected,
              serverUrl: serverBase,
              count: inMemoryVault ? inMemoryVault.length : 0
            };
          }

          case 'GET_CONFIG': {
            const serverBase = await getServerBase();
            return { serverUrl: serverBase, serverConnected };
          }

          case 'SET_CONFIG': {
            const newUrl = normalizeUrl(message.serverUrl);
            const isAlive = await checkServerHealth(newUrl);
            await extAPI.storage.local.set({ serverUrl: newUrl });
            serverConnected = isAlive;
            return { success: true, serverUrl: newUrl, serverConnected: isAlive };
          }

          case 'TEST_SERVER': {
            const testUrl = normalizeUrl(message.serverUrl);
            const start = Date.now();
            const isAlive = await checkServerHealth(testUrl);
            const latency = Date.now() - start;
            return { ok: isAlive, latency };
          }

          case 'UNLOCK_WITH_PRF': {
            const { prfOutput, credentialId } = message;
            if (!prfOutput || prfOutput.length !== 32) {
              throw new Error('Invalid PRF output secret');
            }

            activePrfOutput = new Uint8Array(prfOutput);
            activeAesKey = await VoidVaultCrypto.deriveAesGcmKeyFromPrf(activePrfOutput);

            if (credentialId) {
              await extAPI.storage.local.set({ credentialId });
            }

            // Check local storage or remote server for existing encrypted capsule
            const stored = await extAPI.storage.local.get(['encryptedCapsule', 'syncVersion']);
            let capsule = stored.encryptedCapsule || null;
            syncVersion = stored.syncVersion || 1;

            if (!capsule) {
              // Try pulling from server
              capsule = await pullFromServer(credentialId);
            }

            if (capsule) {
              try {
                inMemoryVault = await VoidVaultCrypto.decryptVaultBlob(capsule, activeAesKey);
                if (!Array.isArray(inMemoryVault)) {
                  inMemoryVault = [];
                }
              } catch (err) {
                console.error('[VoidVault] Decryption failed:', err);
                throw new Error('Decryption failed with this key. Capsule corrupted or key mismatch.');
              }
            } else {
              // Initialize clean fresh vault
              inMemoryVault = [
                {
                  id: 'sample-entry-1',
                  title: 'Demo Portal',
                  domain: 'localhost',
                  username: 'user@voidvault.local',
                  password: 'CorrectHorseBatteryStaple!#2026',
                  notes: 'Initial seed entry for local testing',
                  updatedAt: new Date().toISOString()
                }
              ];
              const newCapsule = await VoidVaultCrypto.encryptVaultBlob(inMemoryVault, activeAesKey);
              await extAPI.storage.local.set({
                encryptedCapsule: newCapsule,
                syncVersion: 1
              });
              pushToServer(newCapsule, 1, credentialId).catch(() => {});
            }

            isUnlocked = true;
            resetAutoLockTimer();
            return { success: true, count: inMemoryVault.length };
          }

          case 'LOCK': {
            lockVault();
            return { success: true };
          }

          case 'RESET_VAULT': {
            lockVault();
            await extAPI.storage.local.remove(['encryptedCapsule', 'syncVersion', 'credentialId']);
            return { success: true };
          }

          case 'GET_ENTRIES': {
            if (!isUnlocked || !inMemoryVault) {
              return { error: 'Vault is locked', isUnlocked: false };
            }
            resetAutoLockTimer();
            const q = (message.query || '').trim().toLowerCase();
            let list = inMemoryVault;
            if (q) {
              list = inMemoryVault.filter(e =>
                (e.title || '').toLowerCase().includes(q) ||
                (e.username || '').toLowerCase().includes(q) ||
                (e.domain || '').toLowerCase().includes(q)
              );
            }
            return { isUnlocked: true, entries: list };
          }

          case 'SAVE_ENTRY': {
            if (!isUnlocked || !inMemoryVault || !activeAesKey) {
              throw new Error('Vault is locked');
            }
            resetAutoLockTimer();
            const entry = message.entry;
            if (!entry || !entry.title) {
              throw new Error('Secret title is required');
            }

            if (!entry.id) {
              entry.id = 'entry_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
              entry.createdAt = new Date().toISOString();
              entry.updatedAt = entry.createdAt;
              inMemoryVault.unshift(entry);
            } else {
              const idx = inMemoryVault.findIndex(e => e.id === entry.id);
              entry.updatedAt = new Date().toISOString();
              if (idx >= 0) {
                inMemoryVault[idx] = { ...inMemoryVault[idx], ...entry };
              } else {
                inMemoryVault.unshift(entry);
              }
            }

            syncVersion += 1;
            const newBlob = await VoidVaultCrypto.encryptVaultBlob(inMemoryVault, activeAesKey);
            await extAPI.storage.local.set({
              encryptedCapsule: newBlob,
              syncVersion
            });

            const storedCred = await extAPI.storage.local.get(['credentialId']);
            pushToServer(newBlob, syncVersion, storedCred.credentialId).catch(() => {});

            return { success: true, entry, syncVersion };
          }

          case 'DELETE_ENTRY': {
            if (!isUnlocked || !inMemoryVault || !activeAesKey) {
              throw new Error('Vault is locked');
            }
            resetAutoLockTimer();
            const id = message.id;
            inMemoryVault = inMemoryVault.filter(e => e.id !== id);

            syncVersion += 1;
            const newBlob = await VoidVaultCrypto.encryptVaultBlob(inMemoryVault, activeAesKey);
            await extAPI.storage.local.set({
              encryptedCapsule: newBlob,
              syncVersion
            });

            const storedCred = await extAPI.storage.local.get(['credentialId']);
            pushToServer(newBlob, syncVersion, storedCred.credentialId).catch(() => {});

            return { success: true, count: inMemoryVault.length };
          }

          case 'AUTOFILL_QUERY': {
            if (!isUnlocked || !inMemoryVault) {
              return { isUnlocked: false, matches: [] };
            }
            const domain = (message.domain || '').toLowerCase().replace(/^www\./, '');
            const matches = inMemoryVault.filter(e => {
              const d = (e.domain || '').toLowerCase().replace(/^www\./, '');
              return d && (domain.includes(d) || d.includes(domain));
            });
            return { isUnlocked: true, matches };
          }

          default:
            return { error: 'Unknown action' };
        }
      } catch (err) {
        return { error: err.message || 'Operation failed' };
      }
    })().then(sendResponse);

    return true; // Keep message channel open for async response
  });
})();
