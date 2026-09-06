/**
 * VoidVault Web Vault Controller
 * Pure client-side zero-knowledge vault connected directly to the VoidVault relay server.
 */

(function () {
  'use strict';

  // State in Volatile Memory
  let activePrfOutput = null;
  let activeAesKey = null;
  let activeSigningKey = null;
  let activeVmkKey = null;
  let activeVmkBytes = null;
  let activeKeySlotId = null;
  let capsuleKeySlots = [];
  let inMemoryVault = [];
  let syncVersion = 1;
  let isUnlocked = false;

  // Timers
  let autoLockInterval = null;
  let idleTimeoutSeconds = 900; // 15 minutes
  let currentIdleSeconds = 900;

  // DOM Elements
  const viewLocked = document.getElementById('view-locked');
  const viewUnlocked = document.getElementById('view-unlocked');
  const errorBox = document.getElementById('error-box');
  const toast = document.getElementById('toast');

  // Header Elements
  const serverStatusBadge = document.getElementById('server-status-badge');
  const serverLatencyLabel = document.getElementById('server-latency-label');
  const btnHeaderLock = document.getElementById('btn-header-lock');
  const btnConfigServer = document.getElementById('btn-config-server');

  // Locked View Elements
  const inputServerUrl = document.getElementById('input-server-url');
  const btnTestPing = document.getElementById('btn-test-ping');
  const pingResult = document.getElementById('ping-result');
  const btnUnlockHw = document.getElementById('btn-unlock-hw');
  const btnDevUnlock = document.getElementById('btn-dev-unlock');

  // Unlocked View Elements
  const activeLocatorText = document.getElementById('active-locator-text');
  const btnCopyLocator = document.getElementById('btn-copy-locator');
  const syncVersionLabel = document.getElementById('sync-version-label');
  const autoLockTimerLabel = document.getElementById('autolock-timer-label');
  const searchInput = document.getElementById('search-input');
  const secretsContainer = document.getElementById('secrets-container');
  const emptyVaultNotice = document.getElementById('empty-vault-notice');
  const btnNewSecret = document.getElementById('btn-new-secret');
  const btnSyncNow = document.getElementById('btn-sync-now');
  const btnExportBackup = document.getElementById('btn-export-backup');

  // Modal Secret
  const modalSecret = document.getElementById('modal-secret');
  const modalTitle = document.getElementById('modal-title');
  const formSecret = document.getElementById('form-secret');
  const fieldId = document.getElementById('field-id');
  const fieldTitle = document.getElementById('field-title');
  const fieldDomain = document.getElementById('field-domain');
  const fieldUsername = document.getElementById('field-username');
  const fieldPassword = document.getElementById('field-password');
  const fieldNotes = document.getElementById('field-notes');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const btnCancelModal = document.getElementById('btn-cancel-modal');
  const btnGeneratePass = document.getElementById('btn-generate-pass');

  // Server Base URL helpers
  function getServerUrl() {
    return localStorage.getItem('voidvault_server_url') || 'http://localhost:8080';
  }

  function setServerUrl(url) {
    let clean = url.trim().replace(/\/+$/, '');
    localStorage.setItem('voidvault_server_url', clean);
    return clean;
  }

  // Toast & Error Notifications
  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.remove('hidden');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => {
      toast.classList.add('hidden');
    }, 2800);
  }

  function showError(msg) {
    if (!errorBox) return;
    errorBox.textContent = msg;
    errorBox.classList.remove('hidden');
  }

  function hideError() {
    if (errorBox) errorBox.classList.add('hidden');
  }

  // Server Ping & Health Check
  async function pingServer(targetUrl = null) {
    const url = targetUrl || getServerUrl();
    const startTime = performance.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${url}/health`, { signal: controller.signal });
      clearTimeout(timer);
      const latency = Math.round(performance.now() - startTime);

      if (res.ok) {
        if (serverStatusBadge) {
          serverStatusBadge.className = 'status-tag status-secure';
          serverStatusBadge.textContent = '● Server Online';
        }
        if (serverLatencyLabel) {
          serverLatencyLabel.textContent = `${latency}ms (${url})`;
        }
        return { ok: true, latency };
      }
    } catch {}

    if (serverStatusBadge) {
      serverStatusBadge.className = 'status-tag status-adversary';
      serverStatusBadge.textContent = '● Server Offline';
    }
    if (serverLatencyLabel) {
      serverLatencyLabel.textContent = `Unreachable (${url})`;
    }
    return { ok: false, latency: null };
  }

  // Server Pull
  async function pullVaultFromServer(locator) {
    const serverBase = getServerUrl();
    try {
      const res = await fetch(`${serverBase}/api/vault/${locator}`);
      if (res.status === 404) {
        return { found: false, capsule: null, version: 1 };
      }
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      const data = await res.json();
      return {
        found: true,
        capsule: data.capsule || null,
        version: typeof data.version === 'number' ? data.version : 1
      };
    } catch (err) {
      console.warn('[VoidVault Web] Pull failed:', err);
      return { found: false, capsule: null, version: 1, error: err.message };
    }
  }

  // Server Push with Ed25519 Signature
  async function pushVaultToServer(encryptedCapsule, version) {
    if (!activeSigningKey) {
      throw new Error('No active signing key to sign vault write');
    }
    const serverBase = getServerUrl();
    const locator = activeSigningKey.locator;

    const signature = await VoidVaultCrypto.signVaultWrite(
      activeSigningKey.privateKey,
      locator,
      version,
      encryptedCapsule
    );

    const res = await fetch(`${serverBase}/api/vault/${locator}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        version: version,
        capsule: encryptedCapsule,
        public_key: activeSigningKey.publicKeyHex,
        signature: signature
      })
    });

    if (res.status === 409) {
      throw new Error('Anti-Rollback Conflict (409): Server has a newer vault version. Please refresh.');
    }
    if (res.status === 429) {
      throw new Error('Rate Limited (429): Too many new vault creations from your IP.');
    }
    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`Server write rejected (${res.status}): ${errText}`);
    }

    return true;
  }

  // Decrypt Capsule
  async function decryptCapsule(capsuleToDecrypt, prfAesKey) {
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
        throw new Error('Your physical security key is not enrolled in this vault.');
      }
      const vmkKey = await VoidVaultCrypto.importVmk(rawVmk);
      const entries = await VoidVaultCrypto.decryptPayloadWithVmk(capsuleToDecrypt.payload, vmkKey);
      return {
        rawVmk,
        vmkKey,
        keySlotId: matchedSlot.id,
        keySlots: capsuleToDecrypt.keySlots,
        entries: Array.isArray(entries) ? entries : []
      };
    } else {
      const entries = await VoidVaultCrypto.decryptVaultBlob(capsuleToDecrypt, prfAesKey);
      return {
        rawVmk: null,
        vmkKey: null,
        keySlotId: 'legacy',
        keySlots: [],
        entries: Array.isArray(entries) ? entries : []
      };
    }
  }

  // Core Unlock Process
  async function completeUnlock(prfBytes, credentialId = null) {
    hideError();
    try {
      activePrfOutput = new Uint8Array(prfBytes);
      activeAesKey = await VoidVaultCrypto.deriveAesGcmKeyFromPrf(activePrfOutput);
      activeSigningKey = await VoidVaultCrypto.deriveSigningKeypairFromPrf(activePrfOutput);

      if (credentialId) {
        localStorage.setItem('voidvault_credential_id', credentialId);
      }

      const locator = activeSigningKey.locator;
      const remote = await pullVaultFromServer(locator);

      if (remote.found && remote.capsule) {
        const decrypted = await decryptCapsule(remote.capsule, activeAesKey);
        inMemoryVault = decrypted.entries;
        activeVmkBytes = decrypted.rawVmk;
        activeVmkKey = decrypted.vmkKey;
        activeKeySlotId = decrypted.keySlotId;
        capsuleKeySlots = decrypted.keySlots;
        syncVersion = remote.version;
        showToast(`Connected to server! Vault loaded (v${syncVersion})`);
      } else {
        // Initialize fresh multi-keyslot vault
        inMemoryVault = [];
        syncVersion = 1;
        activeVmkBytes = VoidVaultCrypto.generateVmkBytes();
        activeVmkKey = await VoidVaultCrypto.importVmk(activeVmkBytes);
        const wrapped = await VoidVaultCrypto.wrapVmk(activeVmkBytes, activeAesKey);
        activeKeySlotId = 'key-primary';
        capsuleKeySlots = [{
          id: activeKeySlotId,
          name: 'Primary YubiKey',
          credentialId: credentialId || 'primary',
          locator: locator,
          publicKey: activeSigningKey.publicKeyHex,
          enrolledAt: new Date().toISOString(),
          wrappedVmk: wrapped
        }];

        // Push initial blank vault
        const encPayload = await VoidVaultCrypto.encryptPayloadWithVmk(inMemoryVault, activeVmkKey);
        const initialCapsule = {
          format: 'voidvault-multi-keyslot-v1',
          version: 2,
          keySlots: capsuleKeySlots,
          payload: encPayload,
          updatedAt: new Date().toISOString()
        };

        try {
          await pushVaultToServer(initialCapsule, syncVersion);
          showToast('Fresh vault initialized and synced to server DB!');
        } catch (pushErr) {
          console.warn('[VoidVault Web] Initial push skipped or offline:', pushErr);
          showToast('Initialized local vault (server push pending)');
        }
      }

      isUnlocked = true;
      showUnlockedView();
      renderSecrets();
      startAutoLockTimer();
    } catch (err) {
      console.error('[VoidVault Web] Unlock failed:', err);
      showError(err.message || 'Failed to unlock vault with security key.');
    }
  }

  // Save vault state and push to server DB
  async function saveAndSync() {
    if (!activeVmkKey || !activeSigningKey) {
      throw new Error('Vault is locked or master key unavailable');
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

    await pushVaultToServer(capsule, syncVersion);
    if (syncVersionLabel) syncVersionLabel.textContent = `v${syncVersion}`;
    showToast('Saved and synced to server database!');
    return true;
  }

  // Auto-Lock Timer
  function startAutoLockTimer() {
    clearInterval(autoLockInterval);
    currentIdleSeconds = idleTimeoutSeconds;
    updateAutoLockDisplay();

    autoLockInterval = setInterval(() => {
      currentIdleSeconds -= 1;
      updateAutoLockDisplay();
      if (currentIdleSeconds <= 0) {
        lockVault();
        showToast('Vault auto-locked due to inactivity');
      }
    }, 1000);
  }

  function resetIdleTimer() {
    currentIdleSeconds = idleTimeoutSeconds;
    updateAutoLockDisplay();
  }

  function updateAutoLockDisplay() {
    if (!autoLockTimerLabel) return;
    const mins = Math.floor(currentIdleSeconds / 60);
    const secs = currentIdleSeconds % 60;
    autoLockTimerLabel.textContent = `${mins}:${secs.toString().padStart(2, '0')}`;
  }

  // Lock Vault
  function lockVault() {
    clearInterval(autoLockInterval);
    if (activePrfOutput) VoidVaultCrypto.zeroBuffer(activePrfOutput);
    if (activeVmkBytes) VoidVaultCrypto.zeroBuffer(activeVmkBytes);

    activePrfOutput = null;
    activeAesKey = null;
    activeSigningKey = null;
    activeVmkKey = null;
    activeVmkBytes = null;
    inMemoryVault = [];
    isUnlocked = false;

    showLockedView();
    showToast('Vault locked. Memory scrubbed.');
  }

  // View Transitions
  function showLockedView() {
    viewLocked.classList.remove('hidden');
    viewUnlocked.classList.add('hidden');
    if (btnHeaderLock) btnHeaderLock.classList.add('hidden');
  }

  function showUnlockedView() {
    viewLocked.classList.add('hidden');
    viewUnlocked.classList.remove('hidden');
    if (btnHeaderLock) btnHeaderLock.classList.remove('hidden');

    if (activeLocatorText && activeSigningKey) {
      activeLocatorText.textContent = activeSigningKey.locator;
    }
    if (syncVersionLabel) {
      syncVersionLabel.textContent = `v${syncVersion}`;
    }
  }

  // Render Secrets List
  function renderSecrets() {
    if (!secretsContainer) return;
    const query = (searchInput?.value || '').trim().toLowerCase();

    const filtered = inMemoryVault.filter(entry => {
      if (!query) return true;
      const title = (entry.title || '').toLowerCase();
      const domain = (entry.domain || '').toLowerCase();
      const user = (entry.username || '').toLowerCase();
      const notes = (entry.notes || '').toLowerCase();
      return title.includes(query) || domain.includes(query) || user.includes(query) || notes.includes(query);
    });

    if (filtered.length === 0) {
      secretsContainer.innerHTML = '';
      if (emptyVaultNotice) {
        emptyVaultNotice.classList.remove('hidden');
        emptyVaultNotice.textContent = query ? 'No credentials match your search.' : 'Your vault is currently empty. Click "+ New Secret" to add your first entry!';
      }
      return;
    }

    if (emptyVaultNotice) emptyVaultNotice.classList.add('hidden');
    secretsContainer.innerHTML = '';

    filtered.forEach(item => {
      const card = document.createElement('div');
      card.className = 'vault-secret-card';

      const domainDisplay = item.domain ? `https://${item.domain.replace(/^https?:\/\//, '')}` : '';

      card.innerHTML = `
        <div class="secret-card-top">
          <div class="secret-card-title-group">
            <h4 class="secret-card-title">${escapeHtml(item.title || 'Untitled Secret')}</h4>
            ${domainDisplay ? `<a href="${escapeHtml(domainDisplay)}" target="_blank" rel="noopener" class="secret-card-link">${escapeHtml(item.domain)} ↗</a>` : ''}
          </div>
          <div class="secret-card-actions">
            <button class="btn-icon btn-edit" title="Edit Secret">✏️</button>
            <button class="btn-icon btn-delete" title="Delete Secret">🗑️</button>
          </div>
        </div>

        <div class="secret-fields-grid">
          <div class="secret-field-row">
            <span class="secret-field-label">Username:</span>
            <span class="secret-field-val">${escapeHtml(item.username || '(None)')}</span>
            ${item.username ? `<button class="btn-sm btn-outline btn-copy-user" title="Copy Username">Copy</button>` : ''}
          </div>
          <div class="secret-field-row">
            <span class="secret-field-label">Password:</span>
            <span class="secret-field-val password-masked" id="pwd-val-${item.id}">••••••••••••••••</span>
            <button class="btn-sm btn-outline btn-toggle-pwd">Show</button>
            <button class="btn-sm btn-primary btn-copy-pwd">Copy</button>
          </div>
          ${item.notes ? `
            <div class="secret-notes-row">
              <span class="secret-field-label">Notes:</span>
              <pre class="secret-notes-val">${escapeHtml(item.notes)}</pre>
            </div>
          ` : ''}
        </div>
      `;

      // Copy Username
      const btnCopyUser = card.querySelector('.btn-copy-user');
      if (btnCopyUser) {
        btnCopyUser.addEventListener('click', () => {
          navigator.clipboard.writeText(item.username);
          showToast('Username copied to clipboard!');
        });
      }

      // Toggle & Copy Password
      const btnTogglePwd = card.querySelector('.btn-toggle-pwd');
      const btnCopyPwd = card.querySelector('.btn-copy-pwd');
      const pwdValEl = card.querySelector(`#pwd-val-${item.id}`);

      let pwdShown = false;
      if (btnTogglePwd && pwdValEl) {
        btnTogglePwd.addEventListener('click', () => {
          pwdShown = !pwdShown;
          if (pwdShown) {
            pwdValEl.textContent = item.password || '';
            pwdValEl.classList.remove('password-masked');
            btnTogglePwd.textContent = 'Hide';
          } else {
            pwdValEl.textContent = '••••••••••••••••';
            pwdValEl.classList.add('password-masked');
            btnTogglePwd.textContent = 'Show';
          }
        });
      }

      if (btnCopyPwd) {
        btnCopyPwd.addEventListener('click', () => {
          navigator.clipboard.writeText(item.password || '');
          showToast('Password copied to clipboard!');
        });
      }

      // Edit Secret
      const btnEdit = card.querySelector('.btn-edit');
      if (btnEdit) {
        btnEdit.addEventListener('click', () => {
          openSecretModal(item);
        });
      }

      // Delete Secret
      const btnDelete = card.querySelector('.btn-delete');
      if (btnDelete) {
        btnDelete.addEventListener('click', async () => {
          if (confirm(`Delete "${item.title || 'this secret'}"? This will be synced to the database.`)) {
            inMemoryVault = inMemoryVault.filter(s => s.id !== item.id);
            renderSecrets();
            try {
              await saveAndSync();
            } catch (err) {
              showError('Delete push failed: ' + err.message);
            }
          }
        });
      }

      secretsContainer.appendChild(card);
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Open Secret Modal for Add or Edit
  function openSecretModal(item = null) {
    hideError();
    if (item) {
      if (modalTitle) modalTitle.textContent = 'Edit Secret';
      if (fieldId) fieldId.value = item.id;
      if (fieldTitle) fieldTitle.value = item.title || '';
      if (fieldDomain) fieldDomain.value = item.domain || '';
      if (fieldUsername) fieldUsername.value = item.username || '';
      if (fieldPassword) fieldPassword.value = item.password || '';
      if (fieldNotes) fieldNotes.value = item.notes || '';
    } else {
      if (modalTitle) modalTitle.textContent = 'Add New Secret';
      if (fieldId) fieldId.value = '';
      if (formSecret) formSecret.reset();
    }
    if (modalSecret) modalSecret.classList.remove('hidden');
  }

  function closeSecretModal() {
    if (modalSecret) modalSecret.classList.add('hidden');
  }

  // Password Generator
  function generatePassword() {
    const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+';
    const bytes = crypto.getRandomValues(new Uint8Array(20));
    let pwd = '';
    for (let i = 0; i < 20; i++) {
      pwd += chars[bytes[i] % chars.length];
    }
    if (fieldPassword) fieldPassword.value = pwd;
    showToast('Strong password generated!');
  }

  // Event Listeners Setup
  function initListeners() {
    // Idle activity tracking
    ['click', 'keydown', 'mousemove', 'scroll'].forEach(evt => {
      window.addEventListener(evt, resetIdleTimer, { passive: true });
    });

    // Server Config
    const storedUrl = getServerUrl();
    if (inputServerUrl) inputServerUrl.value = storedUrl;

    if (btnTestPing) {
      btnTestPing.addEventListener('click', async () => {
        const url = setServerUrl(inputServerUrl.value);
        if (pingResult) pingResult.textContent = 'Pinging...';
        const res = await pingServer(url);
        if (pingResult) {
          pingResult.textContent = res.ok ? `Online (${res.latency}ms)` : 'Unreachable';
          pingResult.className = res.ok ? 'text-success' : 'text-danger';
        }
      });
    }

    if (inputServerUrl) {
      inputServerUrl.addEventListener('change', () => {
        setServerUrl(inputServerUrl.value);
        pingServer();
      });
    }

    // 1. Hardware Security Key: Unified Login & Auto-Register (WebAuthn PRF)
    if (btnUnlockHw) {
      let pendingRegistration = false;

      btnUnlockHw.addEventListener('click', async () => {
        hideError();
        btnUnlockHw.disabled = true;

        try {
          const pinnedCred = localStorage.getItem('voidvault_credential_id');

          if (pendingRegistration) {
            btnUnlockHw.textContent = 'Touch Key to Create Vault...';
            const reg = await VoidVaultCrypto.registerWithWebAuthnPrf({
              username: 'voidvault_user',
              displayName: 'VoidVault User'
            });
            localStorage.setItem('voidvault_credential_id', reg.credentialId);
            let prf = reg.prfOutput;
            if (!prf) {
              btnUnlockHw.textContent = 'Touch Key to Derive PRF...';
              const assertion = await VoidVaultCrypto.authenticateWithWebAuthnPrf({ credentialId: reg.credentialId });
              prf = assertion.prfOutput;
            }
            pendingRegistration = false;
            showToast('Security Key registered! Initializing vault...');
            await completeUnlock(prf, reg.credentialId);
            return;
          }

          btnUnlockHw.textContent = 'Touch Security Key...';

          let authResult = null;
          try {
            authResult = await VoidVaultCrypto.loginOrRegisterWithWebAuthn({
              preferredCredentialId: pinnedCred || null
            });
          } catch (authErr) {
            console.warn('[VoidVault Web] Unified login/register notice:', authErr);
            if (authErr.name === 'AbortError') {
              throw new Error('Authentication cancelled by user.');
            }
            // If browser required a fresh user gesture to register:
            pendingRegistration = true;
            btnUnlockHw.disabled = false;
            btnUnlockHw.textContent = '🛡️ Key Unregistered — Click to Register Key';
            showToast('No vault found on this key. Click above to register.');
            return;
          }

          if (authResult) {
            pendingRegistration = false;
            localStorage.setItem('voidvault_credential_id', authResult.credentialId);
            if (authResult.action === 'register') {
              showToast('Security Key registered! Initializing vault...');
            }
            await completeUnlock(authResult.prfOutput, authResult.credentialId);
          }
        } catch (err) {
          console.error('[VoidVault Web] Login/Register failed:', err);
          showError(err.message || 'Security key touch cancelled or failed');
        } finally {
          if (!pendingRegistration && !isUnlocked) {
            btnUnlockHw.disabled = false;
            btnUnlockHw.textContent = '🔑 Login with Security Key';
          }
        }
      });
    }

    // 2. Dev Simulated Unlock
    if (btnDevUnlock) {
      btnDevUnlock.addEventListener('click', async () => {
        hideError();
        try {
          const prfBytes = await VoidVaultCrypto.deriveSimulatedPrf('voidvault-dev-simulated-key');
          await completeUnlock(prfBytes, 'dev-simulated-key');
        } catch (err) {
          showError(err.message || 'Dev unlock failed');
        }
      });
    }

    // Copy Locator
    if (btnCopyLocator) {
      btnCopyLocator.addEventListener('click', () => {
        if (activeSigningKey && activeSigningKey.locator) {
          navigator.clipboard.writeText(activeSigningKey.locator);
          showToast('Locator hash copied to clipboard!');
        }
      });
    }

    // Search
    if (searchInput) {
      searchInput.addEventListener('input', renderSecrets);
    }

    // New Secret
    if (btnNewSecret) {
      btnNewSecret.addEventListener('click', () => openSecretModal());
    }

    if (btnCloseModal) btnCloseModal.addEventListener('click', closeSecretModal);
    if (btnCancelModal) btnCancelModal.addEventListener('click', closeSecretModal);
    if (btnGeneratePass) btnGeneratePass.addEventListener('click', generatePassword);

    // Save Secret Form
    if (formSecret) {
      formSecret.addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = fieldId.value || ('sec_' + Date.now());
        const title = fieldTitle.value.trim();
        const domain = fieldDomain.value.trim();
        const username = fieldUsername.value.trim();
        const password = fieldPassword.value;
        const notes = fieldNotes.value.trim();

        const existingIdx = inMemoryVault.findIndex(s => s.id === id);
        const secretObj = { id, title, domain, username, password, notes, updatedAt: new Date().toISOString() };

        if (existingIdx >= 0) {
          inMemoryVault[existingIdx] = secretObj;
        } else {
          inMemoryVault.unshift(secretObj);
        }

        closeSecretModal();
        renderSecrets();

        try {
          await saveAndSync();
        } catch (err) {
          showError('Save failed: ' + err.message);
        }
      });
    }

    // Manual Sync
    if (btnSyncNow) {
      btnSyncNow.addEventListener('click', async () => {
        btnSyncNow.disabled = true;
        btnSyncNow.textContent = 'Syncing...';
        try {
          await saveAndSync();
        } catch (err) {
          showError('Sync failed: ' + err.message);
        } finally {
          btnSyncNow.disabled = false;
          btnSyncNow.textContent = 'Sync with Server';
        }
      });
    }

    // Header Lock Button
    if (btnHeaderLock) {
      btnHeaderLock.addEventListener('click', lockVault);
    }

    // Export Backup
    if (btnExportBackup) {
      btnExportBackup.addEventListener('click', async () => {
        if (!activeVmkKey) return;
        const encPayload = await VoidVaultCrypto.encryptPayloadWithVmk(inMemoryVault, activeVmkKey);
        const capsule = {
          format: 'voidvault-multi-keyslot-v1',
          version: 2,
          keySlots: capsuleKeySlots,
          payload: encPayload,
          exportedAt: new Date().toISOString()
        };
        const blob = new Blob([JSON.stringify(capsule, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `voidvault-backup-${new Date().toISOString().slice(0, 10)}.voidvault`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Encrypted .voidvault backup downloaded!');
      });
    }
  }

  // Initial Boot
  document.addEventListener('DOMContentLoaded', () => {
    initListeners();
    pingServer();
    showLockedView();
  });
})();
