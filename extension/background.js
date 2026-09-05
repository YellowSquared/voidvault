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
  let activeVmkBytes = null;
  let activeVmkKey = null;
  let activeKeySlotId = null;
  let capsuleKeySlots = [];
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
    if (activeVmkBytes) {
      VoidVaultCrypto.zeroBuffer(activeVmkBytes);
      activeVmkBytes = null;
    }
    if (inMemoryVault) {
      inMemoryVault.length = 0;
      inMemoryVault = null;
    }
    activeAesKey = null;
    activeVmkKey = null;
    activeKeySlotId = null;
    isUnlocked = false;
    if (autoLockTimerId) {
      clearTimeout(autoLockTimerId);
      autoLockTimerId = null;
    }
    console.log('[VoidVault] Vault locked, volatile memory scrubbed.');
  }

  async function decryptCapsuleWithKey(capsuleToDecrypt, prfAesKey) {
    if (!capsuleToDecrypt) return null;
    if (capsuleToDecrypt.format === 'voidvault-multi-keyslot-v1' && Array.isArray(capsuleToDecrypt.keySlots)) {
      let rawVmk = null;
      let matchedSlot = null;
      for (const slot of capsuleToDecrypt.keySlots) {
        try {
          rawVmk = await VoidVaultCrypto.unwrapVmk(slot.wrappedVmk, prfAesKey);
          matchedSlot = slot;
          break;
        } catch {}
      }
      if (!rawVmk || !matchedSlot) {
        throw new Error('This security key is not enrolled in this vault.');
      }
      const vmkKey = await VoidVaultCrypto.importVmk(rawVmk);
      const entries = await VoidVaultCrypto.decryptPayloadWithVmk(capsuleToDecrypt.payload, vmkKey);
      return {
        legacy: false,
        rawVmk,
        vmkKey,
        keySlotId: matchedSlot.id,
        keySlots: capsuleToDecrypt.keySlots,
        entries: Array.isArray(entries) ? entries : []
      };
    } else {
      const entries = await VoidVaultCrypto.decryptVaultBlob(capsuleToDecrypt, prfAesKey);
      return {
        legacy: true,
        entries: Array.isArray(entries) ? entries : []
      };
    }
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
        return {
          capsule: data?.capsule || null,
          version: typeof data?.version === 'number' ? data.version : 1,
          sha256: data?.capsule_sha256 || null
        };
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

  async function saveAndSyncVault(credentialId = null) {
    if (!activeVmkKey) {
      throw new Error('No active vault master key');
    }
    syncVersion += 1;
    const encPayload = await VoidVaultCrypto.encryptPayloadWithVmk(inMemoryVault, activeVmkKey);
    const capsule = {
      format: 'voidvault-multi-keyslot-v1',
      version: 2,
      keySlots: capsuleKeySlots,
      payload: encPayload,
      updatedAt: new Date().toISOString()
    };
    await extAPI.storage.local.set({
      encryptedCapsule: capsule,
      syncVersion: syncVersion
    });

    const primaryLocator = capsuleKeySlots.length > 0 ? capsuleKeySlots[0].locator : null;
    pushToServer(capsule, syncVersion, credentialId || primaryLocator).catch(() => {});
    return capsule;
  }

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
              count: inMemoryVault ? inMemoryVault.length : 0,
              enrolledKeys: capsuleKeySlots.length
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
            const localCapsule = stored.encryptedCapsule || null;
            const localVersion = typeof stored.syncVersion === 'number' ? stored.syncVersion : 1;
            syncVersion = localVersion;

            let candidateCapsule = localCapsule;
            let candidateVersion = localVersion;
            let usingRemote = false;

            // Probe server for newer state or fallback if local storage is empty
            const remoteData = await pullFromServer(credentialId);
            if (remoteData && remoteData.capsule) {
              const remoteVer = remoteData.version || 1;
              if (localCapsule && remoteVer < localVersion) {
                console.warn(`[VoidVault Security] ROLLBACK DEFENSE: Server has stale version ${remoteVer} < local version ${localVersion}. Rejecting server state.`);
                // Heal server by re-pushing local state
                pushToServer(localCapsule, localVersion, credentialId).catch(() => {});
              } else if (remoteVer > localVersion || !localCapsule) {
                console.log(`[VoidVault Sync] Server candidate is newer (${remoteVer} > ${localVersion}). Validating remote capsule.`);
                candidateCapsule = remoteData.capsule;
                candidateVersion = remoteVer;
                usingRemote = true;
              }
            }

            if (candidateCapsule) {
              try {
                let decrypted = null;
                try {
                  decrypted = await decryptCapsuleWithKey(candidateCapsule, activeAesKey);
                } catch (candidateErr) {
                  if (usingRemote && localCapsule) {
                    console.warn('[VoidVault Security] Remote capsule failed decryption/integrity check! Falling back to trusted local cache.');
                    candidateCapsule = localCapsule;
                    candidateVersion = localVersion;
                    usingRemote = false;
                    decrypted = await decryptCapsuleWithKey(localCapsule, activeAesKey);
                  } else {
                    throw candidateErr;
                  }
                }

                if (decrypted.legacy) {
                  inMemoryVault = decrypted.entries;
                  activeVmkBytes = VoidVaultCrypto.generateVmkBytes();
                  activeVmkKey = await VoidVaultCrypto.importVmk(activeVmkBytes);
                  const wrapped = await VoidVaultCrypto.wrapVmk(activeVmkBytes, activeAesKey);
                  const loc = await getLocator(credentialId);
                  activeKeySlotId = 'key-primary';
                  capsuleKeySlots = [{
                    id: activeKeySlotId,
                    name: 'Primary Security Key',
                    credentialId: credentialId || 'primary',
                    locator: loc,
                    enrolledAt: new Date().toISOString(),
                    wrappedVmk: wrapped
                  }];
                  await saveAndSyncVault(credentialId);
                } else {
                  activeVmkBytes = decrypted.rawVmk;
                  activeVmkKey = decrypted.vmkKey;
                  activeKeySlotId = decrypted.keySlotId;
                  capsuleKeySlots = decrypted.keySlots;
                  inMemoryVault = decrypted.entries;
                  syncVersion = candidateVersion;
                  if (usingRemote) {
                    await extAPI.storage.local.set({
                      encryptedCapsule: candidateCapsule,
                      syncVersion: candidateVersion
                    });
                  }
                }

                if (!Array.isArray(inMemoryVault)) {
                  inMemoryVault = [];
                }
              } catch (err) {
                console.error('[VoidVault] Decryption failed:', err);
                throw new Error(err.message || 'Decryption failed with this key.');
              }
            } else {
              // Initialize brand new vault with multi-keyslot envelope
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
              activeVmkBytes = VoidVaultCrypto.generateVmkBytes();
              activeVmkKey = await VoidVaultCrypto.importVmk(activeVmkBytes);
              const wrapped = await VoidVaultCrypto.wrapVmk(activeVmkBytes, activeAesKey);
              const loc = await getLocator(credentialId);
              activeKeySlotId = 'key-' + Date.now();
              capsuleKeySlots = [{
                id: activeKeySlotId,
                name: 'Primary Security Key',
                credentialId: credentialId || 'primary',
                locator: loc,
                enrolledAt: new Date().toISOString(),
                wrappedVmk: wrapped
              }];
              await saveAndSyncVault(credentialId);
            }

            isUnlocked = true;
            resetAutoLockTimer();
            return {
              success: true,
              count: inMemoryVault.length,
              enrolledKeys: capsuleKeySlots.length
            };
          }

          case 'GET_ENROLLED_KEYS': {
            if (!isUnlocked || !activeVmkKey) {
              return { error: 'Vault is locked', isUnlocked: false };
            }
            resetAutoLockTimer();
            const keys = capsuleKeySlots.map(s => ({
              id: s.id,
              name: s.name,
              locator: s.locator,
              enrolledAt: s.enrolledAt,
              isCurrent: s.id === activeKeySlotId
            }));
            return { isUnlocked: true, currentKeyId: activeKeySlotId, keys };
          }

          case 'ADD_BACKUP_KEY': {
            if (!isUnlocked || !activeVmkBytes) {
              throw new Error('Vault must be unlocked to enroll a backup security key');
            }
            resetAutoLockTimer();
            const { name, prfOutput, credentialId } = message;
            if (!prfOutput || prfOutput.length !== 32) {
              throw new Error('Invalid PRF output from backup security key');
            }

            const backupPrfAesKey = await VoidVaultCrypto.deriveAesGcmKeyFromPrf(new Uint8Array(prfOutput));
            const backupLocator = await getLocator(credentialId);

            if (capsuleKeySlots.some(s => s.locator === backupLocator || (credentialId && s.credentialId === credentialId))) {
              throw new Error('This security key is already enrolled in this vault.');
            }

            const wrappedVmk = await VoidVaultCrypto.wrapVmk(activeVmkBytes, backupPrfAesKey);
            const newSlot = {
              id: 'key-' + Date.now(),
              name: (name || 'Backup Security Key').trim(),
              credentialId: credentialId || ('key-' + Date.now()),
              locator: backupLocator,
              enrolledAt: new Date().toISOString(),
              wrappedVmk: wrappedVmk
            };

            capsuleKeySlots.push(newSlot);
            await saveAndSyncVault();

            const keys = capsuleKeySlots.map(s => ({
              id: s.id,
              name: s.name,
              locator: s.locator,
              enrolledAt: s.enrolledAt,
              isCurrent: s.id === activeKeySlotId
            }));

            return { success: true, keys, newKeyId: newSlot.id };
          }

          case 'REVOKE_KEY': {
            if (!isUnlocked || !activeVmkBytes) {
              throw new Error('Vault is locked');
            }
            resetAutoLockTimer();
            const { keyId } = message;
            if (!keyId) {
              throw new Error('Key ID is required');
            }
            if (keyId === activeKeySlotId) {
              throw new Error('Cannot revoke the security key currently in use.');
            }
            if (capsuleKeySlots.length <= 1) {
              throw new Error('Cannot revoke the only enrolled security key.');
            }

            capsuleKeySlots = capsuleKeySlots.filter(s => s.id !== keyId);
            await saveAndSyncVault();

            const keys = capsuleKeySlots.map(s => ({
              id: s.id,
              name: s.name,
              locator: s.locator,
              enrolledAt: s.enrolledAt,
              isCurrent: s.id === activeKeySlotId
            }));

            return { success: true, keys };
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
            if (!isUnlocked || !inMemoryVault || !activeVmkKey) {
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

            await saveAndSyncVault();
            return { success: true, entry, syncVersion };
          }

          case 'DELETE_ENTRY': {
            if (!isUnlocked || !inMemoryVault || !activeVmkKey) {
              throw new Error('Vault is locked');
            }
            resetAutoLockTimer();
            const id = message.id;
            inMemoryVault = inMemoryVault.filter(e => e.id !== id);

            await saveAndSyncVault();
            return { success: true, count: inMemoryVault.length };
          }

          case 'EXPORT_OFFLINE_BACKUP': {
            if (!isUnlocked || !activeVmkKey) {
              throw new Error('Vault is locked. Unlock to export backup.');
            }
            resetAutoLockTimer();
            const stored = await extAPI.storage.local.get(['encryptedCapsule', 'syncVersion']);
            const backup = {
              format: 'voidvault-backup-v1',
              exportedAt: new Date().toISOString(),
              syncVersion: syncVersion,
              enrolledKeyCount: capsuleKeySlots.length,
              capsule: stored.encryptedCapsule
            };
            return {
              success: true,
              filename: `voidvault-backup-${new Date().toISOString().slice(0, 10)}.voidvault`,
              backupJson: JSON.stringify(backup, null, 2)
            };
          }

          case 'IMPORT_OFFLINE_BACKUP': {
            if (!isUnlocked || !activeAesKey) {
              throw new Error('Vault must be unlocked with an enrolled security key to restore backup');
            }
            resetAutoLockTimer();
            const { backupJson } = message;
            if (!backupJson) {
              throw new Error('No backup data provided');
            }
            let backup;
            try {
              backup = JSON.parse(backupJson);
            } catch {
              throw new Error('Invalid JSON format in backup file');
            }

            const candidateCapsule = backup.capsule || (backup.format === 'voidvault-multi-keyslot-v1' ? backup : null);
            if (!candidateCapsule) {
              throw new Error('Unsupported or missing capsule in backup file');
            }

            const decrypted = await decryptCapsuleWithKey(candidateCapsule, activeAesKey);
            if (!decrypted || decrypted.legacy) {
              throw new Error('Could not restore legacy or unrecognized backup format');
            }

            activeVmkBytes = decrypted.rawVmk;
            activeVmkKey = decrypted.vmkKey;
            activeKeySlotId = decrypted.keySlotId;
            capsuleKeySlots = decrypted.keySlots;
            inMemoryVault = decrypted.entries;
            syncVersion = Math.max(syncVersion + 1, (backup.syncVersion || 0) + 1);
            await saveAndSyncVault();
            return { success: true, count: inMemoryVault.length, syncVersion };
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
