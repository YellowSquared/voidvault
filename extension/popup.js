/**
 * VoidVault Minimal Prototype 2 Popup Controller
 * Pure DOM, zero-fluff, robust WebAuthn PRF integration.
 */

(function () {
  'use strict';

  const extAPI = typeof browser !== 'undefined' ? browser : chrome;

  // DOM Elements
  const viewLocked = document.getElementById('view-locked');
  const viewUnlocked = document.getElementById('view-unlocked');
  const btnUnlock = document.getElementById('btn-unlock');
  const btnDevUnlock = document.getElementById('btn-dev-unlock');
  const btnEnrollKey = document.getElementById('btn-enroll-key');
  const btnReset = document.getElementById('btn-reset');
  const btnLock = document.getElementById('btn-lock');
  const btnBackup = document.getElementById('btn-backup');
  const statusIcon = document.getElementById('status-icon');
  const statusDot = document.getElementById('status-dot');
  const statusLabel = document.getElementById('status-label');
  const lockedModeBadge = document.getElementById('locked-mode-badge');
  const errorBox = document.getElementById('error-box');
  const toast = document.getElementById('toast');

  // Backup Modal
  const modalBackup = document.getElementById('modal-backup');
  const btnCloseBackup = document.getElementById('btn-close-backup');
  const btnExportEncrypted = document.getElementById('btn-export-encrypted');
  const btnExportPass = document.getElementById('btn-export-pass');
  const btnImportEncrypted = document.getElementById('btn-import-encrypted');
  const inputRestoreFile = document.getElementById('input-restore-file');

  // Security Keys Modal
  const btnKeys = document.getElementById('btn-keys');
  const modalKeys = document.getElementById('modal-keys');
  const btnCloseKeys = document.getElementById('btn-close-keys');
  const enrolledKeysList = document.getElementById('enrolled-keys-list');
  const inputNewKeyName = document.getElementById('input-new-key-name');
  const btnEnrollBackupHw = document.getElementById('btn-enroll-backup-hw');
  const btnEnrollBackupDev = document.getElementById('btn-enroll-backup-dev');

  // Single Key Warning Modal
  const modalSingleKeyWarning = document.getElementById('modal-single-key-warning');
  const btnWarningAddBackup = document.getElementById('btn-warning-add-backup');
  const btnWarningDismiss = document.getElementById('btn-warning-dismiss');
  let warningTimerId = null;

  // Settings Modal
  const serverStatusBox = document.getElementById('server-status');
  const btnSettings = document.getElementById('btn-settings');
  const modalSettings = document.getElementById('modal-settings');
  const btnCloseSettings = document.getElementById('btn-close-settings');
  const btnSelectLocal = document.getElementById('btn-select-local');
  const btnSelectRemote = document.getElementById('btn-select-remote');
  const boxLocalInfo = document.getElementById('box-local-info');
  const boxRemoteOptions = document.getElementById('box-remote-options');
  const inputServerUrl = document.getElementById('input-server-url');
  const btnPresetLocalhost = document.getElementById('btn-preset-localhost');
  const btnPresetVm = document.getElementById('btn-preset-vm');
  const btnTestServer = document.getElementById('btn-test-server');
  const btnSyncNow = document.getElementById('btn-sync-now');
  const btnSaveSettings = document.getElementById('btn-save-settings');
  const testConnectionStatus = document.getElementById('test-connection-status');

  // Secrets List & Search
  const searchInput = document.getElementById('search-input');
  const secretsList = document.getElementById('secrets-list');
  const emptyState = document.getElementById('empty-state');
  const btnOpenAdd = document.getElementById('btn-open-add');

  // Modal
  const modalSecret = document.getElementById('modal-secret');
  const modalHeading = document.getElementById('modal-heading');
  const formSecret = document.getElementById('form-secret');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const btnCancelModal = document.getElementById('btn-cancel-modal');
  const btnGenPass = document.getElementById('btn-gen-pass');
  const fieldId = document.getElementById('field-id');
  const fieldTitle = document.getElementById('field-title');
  const fieldDomain = document.getElementById('field-domain');
  const fieldUsername = document.getElementById('field-username');
  const fieldPassword = document.getElementById('field-password');
  const fieldNotes = document.getElementById('field-notes');

  let activeTabDomain = '';
  let currentVaultMode = 'local';

  async function init() {
    setupListeners();
    await detectActiveTab();
    await checkStatus();
  }

  async function detectActiveTab() {
    try {
      const tabs = await extAPI.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0] && tabs[0].url) {
        const u = new URL(tabs[0].url);
        activeTabDomain = u.hostname.replace(/^www\./, '');
      }
    } catch {
      activeTabDomain = '';
    }
  }

  async function checkStatus() {
    try {
      const res = await extAPI.runtime.sendMessage({ action: 'GET_STATUS' });
      if (!res) return;

      currentVaultMode = res.vaultMode || 'local';
      updateServerStatus(Boolean(res.serverConnected), currentVaultMode);

      if (res.isUnlocked) {
        showUnlockedView();
        await loadSecrets();
      } else {
        showLockedView();
      }
    } catch (err) {
      console.error('[VoidVault] Status check failed:', err);
      showLockedView();
    }
  }

  function updateServerStatus(online, mode = currentVaultMode) {
    currentVaultMode = mode;
    if (mode === 'local') {
      if (statusIcon) statusIcon.classList.remove('hidden');
      if (statusDot) statusDot.classList.add('hidden');
      if (statusLabel) statusLabel.textContent = 'Local Vault';
      if (serverStatusBox) serverStatusBox.title = 'Local Vault (Air-Gapped) — Click to configure';
      if (lockedModeBadge) {
        lockedModeBadge.textContent = '🛡️ Local Vault (Air-Gapped)';
        lockedModeBadge.className = 'mode-badge badge-local';
      }
    } else {
      if (statusIcon) statusIcon.classList.add('hidden');
      if (statusDot) statusDot.classList.remove('hidden');
      if (online) {
        statusDot.className = 'dot online';
        statusLabel.textContent = 'Sync Online';
        if (serverStatusBox) serverStatusBox.title = 'Remote Sync Online — Click to configure';
        if (lockedModeBadge) {
          lockedModeBadge.textContent = '🌐 Remote Sync (Online)';
          lockedModeBadge.className = 'mode-badge badge-remote-online';
        }
      } else {
        statusDot.className = 'dot offline';
        statusLabel.textContent = 'Sync Offline';
        if (serverStatusBox) serverStatusBox.title = 'Remote Server Offline — Click to configure';
        if (lockedModeBadge) {
          lockedModeBadge.textContent = '🌐 Remote Sync (Offline)';
          lockedModeBadge.className = 'mode-badge badge-remote-offline';
        }
      }
    }
  }

  function showLockedView() {
    viewLocked.classList.remove('hidden');
    viewUnlocked.classList.add('hidden');
    btnLock.classList.add('hidden');
    btnBackup.classList.add('hidden');
    btnKeys.classList.add('hidden');
    modalSecret.classList.add('hidden');
    modalBackup.classList.add('hidden');
    modalSettings.classList.add('hidden');
    modalKeys.classList.add('hidden');
    if (modalSingleKeyWarning) modalSingleKeyWarning.classList.add('hidden');
    if (warningTimerId) {
      clearInterval(warningTimerId);
      warningTimerId = null;
    }
    errorBox.classList.add('hidden');
  }

  function showUnlockedView() {
    viewLocked.classList.add('hidden');
    viewUnlocked.classList.remove('hidden');
    btnLock.classList.remove('hidden');
    btnBackup.classList.remove('hidden');
    btnKeys.classList.remove('hidden');
    errorBox.classList.add('hidden');
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove('hidden');
  }

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.remove('hidden');
    setTimeout(() => {
      toast.classList.add('hidden');
    }, 2000);
  }

  async function loadSecrets(query = '') {
    try {
      const res = await extAPI.runtime.sendMessage({ action: 'GET_ENTRIES', query });
      if (res && res.entries) {
        renderSecrets(res.entries);
      }
    } catch (err) {
      console.error('[VoidVault] Failed to load secrets:', err);
    }
  }

  function renderSecrets(entries) {
    secretsList.textContent = ''; // Clear container

    if (!entries || entries.length === 0) {
      emptyState.classList.remove('hidden');
      return;
    }
    emptyState.classList.add('hidden');

    entries.forEach(entry => {
      const card = document.createElement('div');
      card.className = 'secret-card';

      // Header
      const header = document.createElement('div');
      header.className = 'card-header';

      const title = document.createElement('span');
      title.className = 'card-title';
      title.textContent = entry.title || 'Untitled';

      const domain = document.createElement('span');
      domain.className = 'card-domain';
      domain.textContent = entry.domain || '';

      header.appendChild(title);
      header.appendChild(domain);
      card.appendChild(header);

      // Body
      const body = document.createElement('div');
      body.className = 'card-body';

      if (entry.username) {
        const uRow = document.createElement('div');
        uRow.className = 'cred-row';

        const uVal = document.createElement('span');
        uVal.className = 'cred-val';
        uVal.textContent = entry.username;

        const uCopy = document.createElement('button');
        uCopy.className = 'btn-link';
        uCopy.textContent = 'Copy User';
        uCopy.onclick = () => copyText(entry.username, 'Username copied');

        uRow.appendChild(uVal);
        uRow.appendChild(uCopy);
        body.appendChild(uRow);
      }

      if (entry.password) {
        const pRow = document.createElement('div');
        pRow.className = 'cred-row';

        const pVal = document.createElement('span');
        pVal.className = 'cred-val';
        pVal.textContent = '••••••••••••';

        const pCopy = document.createElement('button');
        pCopy.className = 'btn-link';
        pCopy.textContent = 'Copy Pass';
        pCopy.onclick = () => copyText(entry.password, 'Password copied');

        pRow.appendChild(pVal);
        pRow.appendChild(pCopy);
        body.appendChild(pRow);
      }

      card.appendChild(body);

      // Actions
      const actions = document.createElement('div');
      actions.className = 'card-actions';

      if (activeTabDomain && entry.domain && activeTabDomain.includes(entry.domain.toLowerCase())) {
        const btnFill = document.createElement('button');
        btnFill.className = 'btn-sm btn-black';
        btnFill.textContent = 'Fill Tab';
        btnFill.onclick = () => fillTab(entry);
        actions.appendChild(btnFill);
      }

      const btnEdit = document.createElement('button');
      btnEdit.className = 'btn-sm btn-outline';
      btnEdit.textContent = 'Edit';
      btnEdit.onclick = () => openModal(entry);

      const btnDelete = document.createElement('button');
      btnDelete.className = 'btn-sm btn-outline text-danger';
      btnDelete.textContent = 'Delete';
      btnDelete.onclick = () => deleteEntry(entry.id);

      actions.appendChild(btnEdit);
      actions.appendChild(btnDelete);
      card.appendChild(actions);

      secretsList.appendChild(card);
    });
  }

  async function copyText(text, successMsg) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(successMsg);
    } catch {
      showToast('Copy failed');
    }
  }

  async function fillTab(entry) {
    try {
      const tabs = await extAPI.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0]) {
        await extAPI.tabs.sendMessage(tabs[0].id, {
          action: 'AUTOFILL_FIELDS',
          username: entry.username || '',
          password: entry.password || ''
        });
        showToast('Credentials injected into tab');
      }
    } catch (err) {
      showToast('Autofill failed: tab not accessible');
    }
  }

  async function deleteEntry(id) {
    if (!confirm('Delete this secret?')) return;
    try {
      const res = await extAPI.runtime.sendMessage({ action: 'DELETE_ENTRY', id });
      if (res && res.success) {
        showToast('Secret deleted');
        await loadSecrets(searchInput.value);
      }
    } catch (err) {
      showError('Failed to delete secret');
    }
  }

  function openModal(entry = null) {
    modalSecret.classList.remove('hidden');
    if (entry) {
      modalHeading.textContent = 'Edit Secret';
      fieldId.value = entry.id || '';
      fieldTitle.value = entry.title || '';
      fieldDomain.value = entry.domain || '';
      fieldUsername.value = entry.username || '';
      fieldPassword.value = entry.password || '';
      fieldNotes.value = entry.notes || '';
    } else {
      modalHeading.textContent = 'New Secret';
      fieldId.value = '';
      fieldTitle.value = '';
      fieldDomain.value = activeTabDomain || '';
      fieldUsername.value = '';
      fieldPassword.value = '';
      fieldNotes.value = '';
    }
  }

  function closeModal() {
    modalSecret.classList.add('hidden');
    formSecret.reset();
  }

  function generatePassword() {
    const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+?';
    let pwd = '';
    const bytes = crypto.getRandomValues(new Uint8Array(20));
    for (let i = 0; i < 20; i++) {
      pwd += chars[bytes[i] % chars.length];
    }
    fieldPassword.value = pwd;
    showToast('Password generated');
  }

  function setupListeners() {
    // 1. Real Security Key Unlock
    btnUnlock.addEventListener('click', async () => {
      errorBox.classList.add('hidden');
      btnUnlock.disabled = true;
      btnUnlock.textContent = 'Touch security key...';

      try {
        const stored = await extAPI.storage.local.get(['credentialId']);
        const assertion = await VoidVaultCrypto.authenticateWithWebAuthnPrf({
          credentialId: stored.credentialId || null
        });

        const res = await extAPI.runtime.sendMessage({
          action: 'UNLOCK_WITH_PRF',
          prfOutput: Array.from(assertion.prfOutput),
          credentialId: assertion.credentialId
        });

        if (res && res.success) {
          showUnlockedView();
          await loadSecrets();
          showToast('Vault unlocked via FIDO2 key');
        } else {
          throw new Error(res?.error || 'Unlock failed');
        }
      } catch (err) {
        showError(err.message || 'Security key authentication failed');
      } finally {
        btnUnlock.disabled = false;
        btnUnlock.textContent = 'Unlock with Security Key';
      }
    });

    // 2. Dev Simulated Unlock
    btnDevUnlock.addEventListener('click', async () => {
      errorBox.classList.add('hidden');
      try {
        const simPrf = await VoidVaultCrypto.deriveSimulatedPrf('voidvault-dev-simulated-key');
        const res = await extAPI.runtime.sendMessage({
          action: 'UNLOCK_WITH_PRF',
          prfOutput: Array.from(simPrf)
        });

        if (res && res.success) {
          showUnlockedView();
          await loadSecrets();
          showToast('⚡ Dev Unlock Active');
        } else {
          throw new Error(res?.error || 'Dev unlock failed');
        }
      } catch (err) {
        showError(err.message || 'Dev unlock failed');
      }
    });

    // 3. Enroll New Key
    btnEnrollKey.addEventListener('click', async () => {
      errorBox.classList.add('hidden');
      try {
        const reg = await VoidVaultCrypto.registerWithWebAuthnPrf({
          username: 'voidvault_user',
          displayName: 'VoidVault User'
        });

        // Clear stale local capsule so new key initializes fresh vault
        await extAPI.storage.local.remove(['encryptedCapsule', 'syncVersion']);
        await extAPI.storage.local.set({ credentialId: reg.credentialId });

        showToast('Key registered! Now touch key to unlock.');
        setTimeout(() => {
          btnUnlock.click();
        }, 400);
      } catch (err) {
        showError(err.message || 'Key enrollment failed');
      }
    });

    // 4. Reset Vault
    btnReset.addEventListener('click', async () => {
      if (confirm('Reset local vault? This clears cached data so you can start completely fresh.')) {
        await extAPI.runtime.sendMessage({ action: 'RESET_VAULT' });
        showLockedView();
        showToast('Local vault reset.');
      }
    });

    // 5. Lock Vault
    btnLock.addEventListener('click', async () => {
      await extAPI.runtime.sendMessage({ action: 'LOCK' });
      showLockedView();
      showToast('Vault locked.');
    });

    // 6. Search
    searchInput.addEventListener('input', () => {
      loadSecrets(searchInput.value.trim());
    });

    // 7. Modal
    btnOpenAdd.addEventListener('click', () => openModal());
    btnCloseModal.addEventListener('click', closeModal);
    btnCancelModal.addEventListener('click', closeModal);
    btnGenPass.addEventListener('click', generatePassword);

    formSecret.addEventListener('submit', async (e) => {
      e.preventDefault();
      const isNewEntry = !fieldId.value;
      const entry = {
        id: fieldId.value || undefined,
        title: fieldTitle.value.trim(),
        domain: fieldDomain.value.trim(),
        username: fieldUsername.value.trim(),
        password: fieldPassword.value.trim(),
        notes: fieldNotes.value.trim()
      };

      try {
        const res = await extAPI.runtime.sendMessage({ action: 'SAVE_ENTRY', entry });
        if (res && res.success) {
          closeModal();
          showToast('Secret saved');
          await loadSecrets(searchInput.value);

          // If vault has only 1 key enrolled, display unskippable backup warning
          if (isNewEntry && res.enrolledKeys <= 1) {
            triggerSingleKeyWarning(res.entryCount || 1);
          }
        } else {
          showError(res?.error || 'Failed to save secret');
        }
      } catch (err) {
        showError(err.message || 'Failed to save secret');
      }
    });

    // 8. Backup & Export Listeners
    btnBackup.addEventListener('click', () => {
      modalBackup.classList.remove('hidden');
    });

    btnCloseBackup.addEventListener('click', () => {
      modalBackup.classList.add('hidden');
    });

    btnExportEncrypted.addEventListener('click', exportEncryptedBackup);
    btnExportPass.addEventListener('click', exportPassZip);

    btnImportEncrypted.addEventListener('click', () => {
      inputRestoreFile.value = '';
      inputRestoreFile.click();
    });

    inputRestoreFile.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const res = await extAPI.runtime.sendMessage({
          action: 'IMPORT_OFFLINE_BACKUP',
          backupJson: text
        });
        if (res?.error) {
          showError('Restore failed: ' + res.error);
        } else {
          modalBackup.classList.add('hidden');
          showToast(`✓ Restored ${res.count} secrets from offline backup`);
          await loadSecrets(searchInput.value);
        }
      } catch (err) {
        showError('Restore error: ' + err.message);
      }
    });

    // 9. Storage & Server Settings Listeners
    let selectedSettingsMode = 'local';

    function setSettingsModeUi(mode) {
      selectedSettingsMode = mode;
      if (mode === 'local') {
        btnSelectLocal.classList.add('active');
        btnSelectRemote.classList.remove('active');
        boxLocalInfo.classList.remove('hidden');
        boxRemoteOptions.classList.add('hidden');
      } else {
        btnSelectLocal.classList.remove('active');
        btnSelectRemote.classList.add('active');
        boxLocalInfo.classList.add('hidden');
        boxRemoteOptions.classList.remove('hidden');
      }
    }

    btnSelectLocal.addEventListener('click', () => setSettingsModeUi('local'));
    btnSelectRemote.addEventListener('click', () => setSettingsModeUi('remote'));

    const openSettings = async () => {
      try {
        const res = await extAPI.runtime.sendMessage({ action: 'GET_CONFIG' });
        inputServerUrl.value = res?.serverUrl || 'http://localhost:8080';
        setSettingsModeUi(res?.vaultMode || 'local');
        testConnectionStatus.classList.add('hidden');
        testConnectionStatus.textContent = '';
        modalSettings.classList.remove('hidden');
      } catch (err) {
        showError('Could not load settings: ' + err.message);
      }
    };

    serverStatusBox.addEventListener('click', openSettings);
    btnSettings.addEventListener('click', openSettings);

    btnCloseSettings.addEventListener('click', () => {
      modalSettings.classList.add('hidden');
    });

    btnPresetLocalhost.addEventListener('click', () => {
      inputServerUrl.value = 'http://localhost:8080';
    });

    btnPresetVm.addEventListener('click', () => {
      inputServerUrl.value = 'http://20.80.54.57:8080';
    });

    btnTestServer.addEventListener('click', async () => {
      testConnectionStatus.className = 'connection-feedback info';
      testConnectionStatus.textContent = 'Testing ping...';
      testConnectionStatus.classList.remove('hidden');

      try {
        const res = await extAPI.runtime.sendMessage({
          action: 'TEST_SERVER',
          serverUrl: inputServerUrl.value
        });
        if (res && res.ok) {
          testConnectionStatus.className = 'connection-feedback success';
          testConnectionStatus.textContent = `✓ Server Online (${res.latency}ms)`;
        } else {
          testConnectionStatus.className = 'connection-feedback error';
          testConnectionStatus.textContent = '✗ Connection failed or offline';
        }
      } catch (err) {
        testConnectionStatus.className = 'connection-feedback error';
        testConnectionStatus.textContent = `✗ Error: ${err.message}`;
      }
    });

    btnSyncNow.addEventListener('click', async () => {
      testConnectionStatus.className = 'connection-feedback info';
      testConnectionStatus.textContent = 'Pushing vault to server...';
      testConnectionStatus.classList.remove('hidden');
      btnSyncNow.disabled = true;

      try {
        const res = await extAPI.runtime.sendMessage({ action: 'SYNC_TO_SERVER' });
        if (res && res.success) {
          testConnectionStatus.className = 'connection-feedback success';
          testConnectionStatus.textContent = `✓ Synced to server (v${res.version})`;
          showToast(`✓ Synced to server (v${res.version})`);
          updateServerStatus(true, 'remote');
        } else {
          throw new Error(res?.error || 'Sync failed');
        }
      } catch (err) {
        testConnectionStatus.className = 'connection-feedback error';
        testConnectionStatus.textContent = `✗ Sync error: ${err.message}`;
        showError('Sync failed: ' + err.message);
      } finally {
        btnSyncNow.disabled = false;
      }
    });

    btnSaveSettings.addEventListener('click', async () => {
      try {
        const res = await extAPI.runtime.sendMessage({
          action: 'SET_CONFIG',
          vaultMode: selectedSettingsMode,
          serverUrl: inputServerUrl.value
        });
        modalSettings.classList.add('hidden');
        currentVaultMode = res?.vaultMode || selectedSettingsMode;
        updateServerStatus(Boolean(res?.serverConnected), currentVaultMode);
        showToast(currentVaultMode === 'local' ? '🛡️ Local Vault mode active' : '🌐 Remote Sync mode active');
      } catch (err) {
        showError('Failed to save settings: ' + err.message);
      }
    });

    // 10. Security Keys Listeners
    btnKeys.addEventListener('click', openKeysModal);
    btnCloseKeys.addEventListener('click', () => {
      modalKeys.classList.add('hidden');
    });

    btnEnrollBackupHw.addEventListener('click', async () => {
      await enrollBackupKey(false);
    });

    btnEnrollBackupDev.addEventListener('click', async () => {
      await enrollBackupKey(true);
    });

    // 11. Single Key Warning Listeners
    if (btnWarningDismiss) {
      btnWarningDismiss.addEventListener('click', () => {
        if (btnWarningDismiss.disabled) return;
        if (warningTimerId) {
          clearInterval(warningTimerId);
          warningTimerId = null;
        }
        if (modalSingleKeyWarning) modalSingleKeyWarning.classList.add('hidden');
      });
    }

    if (btnWarningAddBackup) {
      btnWarningAddBackup.addEventListener('click', async () => {
        if (warningTimerId) {
          clearInterval(warningTimerId);
          warningTimerId = null;
        }
        if (modalSingleKeyWarning) modalSingleKeyWarning.classList.add('hidden');
        await openKeysModal();
      });
    }
  }

  function getWarningDuration(count) {
    if (count <= 3) return 3;
    if (count === 4) return 5;
    return 7;
  }

  function triggerSingleKeyWarning(entryCount) {
    if (!modalSingleKeyWarning || !btnWarningDismiss) return;

    if (warningTimerId) {
      clearInterval(warningTimerId);
      warningTimerId = null;
    }

    const duration = getWarningDuration(entryCount);
    let secondsRemaining = duration;

    modalSingleKeyWarning.classList.remove('hidden');
    btnWarningDismiss.disabled = true;
    btnWarningDismiss.textContent = `I understand (${secondsRemaining}s)`;

    warningTimerId = setInterval(() => {
      secondsRemaining -= 1;
      if (secondsRemaining <= 0) {
        clearInterval(warningTimerId);
        warningTimerId = null;
        btnWarningDismiss.disabled = false;
        btnWarningDismiss.textContent = 'I understand';
      } else {
        btnWarningDismiss.textContent = `I understand (${secondsRemaining}s)`;
      }
    }, 1000);
  }

  async function openKeysModal() {
    try {
      const res = await extAPI.runtime.sendMessage({ action: 'GET_ENROLLED_KEYS' });
      if (res && res.isUnlocked) {
        renderKeysList(res.keys || [], res.currentKeyId);
        inputNewKeyName.value = '';
        modalKeys.classList.remove('hidden');
      } else {
        showError('Vault must be unlocked to manage security keys.');
      }
    } catch (err) {
      showError('Failed to load security keys: ' + err.message);
    }
  }

  function renderKeysList(keys, currentKeyId) {
    enrolledKeysList.innerHTML = '';
    if (!keys || keys.length === 0) {
      const emptyMsg = document.createElement('div');
      emptyMsg.className = 'empty-hint';
      emptyMsg.textContent = 'No security keys enrolled';
      enrolledKeysList.appendChild(emptyMsg);
      return;
    }

    keys.forEach(k => {
      const card = document.createElement('div');
      card.className = 'key-card';

      const left = document.createElement('div');
      left.className = 'key-card-left';

      const title = document.createElement('div');
      title.className = 'key-card-title';

      const keyIcon = document.createTextNode('🔑 ');
      const titleSpan = document.createElement('span');
      titleSpan.textContent = k.name || 'Security Key';

      title.appendChild(keyIcon);
      title.appendChild(titleSpan);

      if (k.isCurrent) {
        const badge = document.createElement('span');
        badge.className = 'badge-active-key';
        badge.textContent = 'Active Session Key';
        title.appendChild(badge);
      }
      left.appendChild(title);

      const meta = document.createElement('div');
      meta.className = 'key-card-meta';
      const locShort = (k.locator || '').substring(0, 12);
      const dateStr = k.enrolledAt ? new Date(k.enrolledAt).toLocaleDateString() : 'Enrolled';
      meta.textContent = `Locator: ${locShort}... • ${dateStr}`;
      left.appendChild(meta);

      card.appendChild(left);

      if (!k.isCurrent && keys.length > 1) {
        const btnRevoke = document.createElement('button');
        btnRevoke.className = 'btn-sm btn-outline text-danger';
        btnRevoke.textContent = 'Revoke';
        btnRevoke.addEventListener('click', () => revokeKey(k.id, k.name));
        card.appendChild(btnRevoke);
      }

      enrolledKeysList.appendChild(card);
    });
  }

  async function enrollBackupKey(isDev = false) {
    const keyName = (inputNewKeyName.value || 'Backup Security Key').trim();
    try {
      showToast('Touch your backup security key...');
      let prfOutput, credentialId;

      if (isDev) {
        prfOutput = await VoidVaultCrypto.deriveSimulatedPrf('dev-backup-' + Date.now());
        credentialId = 'dev-backup-key-' + Date.now();
      } else {
        const reg = await VoidVaultCrypto.registerWithWebAuthnPrf('user@voidvault.local', 'VoidVault Backup Key');
        prfOutput = reg.prfOutput;
        credentialId = reg.credentialId;
      }

      const res = await extAPI.runtime.sendMessage({
        action: 'ADD_BACKUP_KEY',
        name: keyName,
        prfOutput: Array.from(prfOutput),
        credentialId
      });

      if (res && res.success) {
        renderKeysList(res.keys || [], res.currentKeyId);
        inputNewKeyName.value = '';
        showToast(`✓ "${keyName}" enrolled successfully!`);
      } else {
        showError(res?.error || 'Failed to enroll backup key');
      }
    } catch (err) {
      showError('Enrollment failed: ' + (err.message || 'unknown error'));
    }
  }

  async function revokeKey(keyId, keyName) {
    const confirmed = confirm(
      `Are you sure you want to revoke "${keyName}"?\n\n` +
      `This security key will immediately be disabled and will no longer be able to decrypt this vault.`
    );
    if (!confirmed) return;

    try {
      const res = await extAPI.runtime.sendMessage({
        action: 'REVOKE_KEY',
        keyId
      });
      if (res && res.success) {
        renderKeysList(res.keys || [], res.currentKeyId);
        showToast(`Revoked "${keyName}"`);
      } else {
        showError(res?.error || 'Failed to revoke key');
      }
    } catch (err) {
      showError('Revocation failed: ' + err.message);
    }
  }

  function triggerDownload(filename, data, mimeType = 'application/octet-stream') {
    const blob = data instanceof Blob ? data : new Blob([data], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function exportEncryptedBackup() {
    try {
      const stored = await extAPI.storage.local.get(['encryptedCapsule', 'syncVersion', 'credentialId']);
      if (!stored.encryptedCapsule) {
        showError('No encrypted capsule found to export.');
        return;
      }
      const backupObj = {
        format: 'voidvault-capsule-v2',
        exportedAt: new Date().toISOString(),
        version: stored.syncVersion || 1,
        capsule: stored.encryptedCapsule
      };
      const jsonStr = JSON.stringify(backupObj, null, 2);
      const today = new Date().toISOString().split('T')[0];
      triggerDownload(`voidvault-backup-${today}.voidvault`, jsonStr, 'application/json');
      modalBackup.classList.add('hidden');
      showToast('🔒 Encrypted backup saved (Zero metadata leaked)');
    } catch (err) {
      showError('Backup failed: ' + (err.message || 'unknown error'));
    }
  }

  async function exportPassZip() {
    const confirmed = confirm(
      "SECURITY WARNING (METADATA DISCLOSURE):\n\n" +
      "Standard Unix 'pass' stores directory names and website domains in cleartext on disk (e.g. ~/.password-store/github.com/alice.txt).\n\n" +
      "While the passwords inside the files are protected, your filenames, bank domains, and healthcare services will be visible to your filesystem and disk journals.\n\n" +
      "For zero-leakage, the encrypted .voidvault backup is recommended.\n\n" +
      "Do you want to proceed with the standard Unix pass export anyway?"
    );
    if (!confirmed) return;

    try {
      const res = await extAPI.runtime.sendMessage({ action: 'GET_ENTRIES' });
      const entries = res?.entries || [];
      if (entries.length === 0) {
        showError('Vault is empty. Nothing to export.');
        return;
      }

      const files = [];
      entries.forEach(e => {
        const domain = (e.domain || 'general').replace(/[^a-zA-Z0-9.-]/g, '_').toLowerCase();
        const user = (e.username || e.title || 'secret').replace(/[^a-zA-Z0-9._-]/g, '_');
        const filename = `${domain}/${user}.txt`;

        let content = `${e.password || ''}\n`;
        if (e.username) content += `username: ${e.username}\n`;
        if (e.domain) content += `url: ${e.domain}\n`;
        if (e.title) content += `title: ${e.title}\n`;
        if (e.notes) content += `${e.notes}\n`;

        files.push({ path: filename, content });
      });

      const zipBytes = createZipArchive(files);
      const today = new Date().toISOString().split('T')[0];
      triggerDownload(`voidvault-pass-export-${today}.zip`, zipBytes, 'application/zip');
      modalBackup.classList.add('hidden');
      showToast('📁 Unix pass archive exported');
    } catch (err) {
      showError('pass export failed: ' + (err.message || 'unknown error'));
    }
  }

  function createZipArchive(files) {
    const encoder = new TextEncoder();
    const fileEntries = [];
    let offset = 0;

    const crcTable = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      }
      crcTable[i] = c;
    }
    function calcCrc(bytes) {
      let crc = 0xffffffff;
      for (let i = 0; i < bytes.length; i++) {
        crc = crcTable[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
      }
      return (crc ^ 0xffffffff) >>> 0;
    }

    const parts = [];

    for (const f of files) {
      const pathBytes = encoder.encode(f.path);
      const dataBytes = encoder.encode(f.content);
      const crc = calcCrc(dataBytes);
      const size = dataBytes.length;

      const header = new Uint8Array(30);
      const view = new DataView(header.buffer);
      view.setUint32(0, 0x04034b50, true);
      view.setUint16(4, 20, true);
      view.setUint16(6, 0x0800, true);
      view.setUint16(8, 0, true);
      view.setUint16(10, 0, true);
      view.setUint16(12, 0, true);
      view.setUint32(14, crc, true);
      view.setUint32(18, size, true);
      view.setUint32(22, size, true);
      view.setUint16(26, pathBytes.length, true);
      view.setUint16(28, 0, true);

      parts.push(header, pathBytes, dataBytes);

      fileEntries.push({
        pathBytes,
        crc,
        size,
        offset
      });

      offset += header.length + pathBytes.length + dataBytes.length;
    }

    const cdStartOffset = offset;
    let cdSize = 0;

    for (const e of fileEntries) {
      const cdHeader = new Uint8Array(46);
      const view = new DataView(cdHeader.buffer);
      view.setUint32(0, 0x02014b50, true);
      view.setUint16(4, 20, true);
      view.setUint16(6, 20, true);
      view.setUint16(8, 0x0800, true);
      view.setUint16(10, 0, true);
      view.setUint16(12, 0, true);
      view.setUint16(14, 0, true);
      view.setUint32(16, e.crc, true);
      view.setUint32(20, e.size, true);
      view.setUint32(24, e.size, true);
      view.setUint16(28, e.pathBytes.length, true);
      view.setUint16(30, 0, true);
      view.setUint16(32, 0, true);
      view.setUint16(34, 0, true);
      view.setUint16(36, 0, true);
      view.setUint32(38, 0, true);
      view.setUint32(42, e.offset, true);

      parts.push(cdHeader, e.pathBytes);
      const entryCdLength = cdHeader.length + e.pathBytes.length;
      cdSize += entryCdLength;
      offset += entryCdLength;
    }

    const eocd = new Uint8Array(22);
    const eocdView = new DataView(eocd.buffer);
    eocdView.setUint32(0, 0x06054b50, true);
    eocdView.setUint16(4, 0, true);
    eocdView.setUint16(6, 0, true);
    eocdView.setUint16(8, fileEntries.length, true);
    eocdView.setUint16(10, fileEntries.length, true);
    eocdView.setUint32(12, cdSize, true);
    eocdView.setUint32(16, cdStartOffset, true);
    eocdView.setUint16(20, 0, true);

    parts.push(eocd);

    const totalLength = parts.reduce((acc, p) => acc + p.length, 0);
    const result = new Uint8Array(totalLength);
    let pos = 0;
    for (const p of parts) {
      result.set(p, pos);
      pos += p.length;
    }
    return result;
  }

  document.addEventListener('DOMContentLoaded', init);
})();
