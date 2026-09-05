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
  const statusDot = document.getElementById('status-dot');
  const statusLabel = document.getElementById('status-label');
  const errorBox = document.getElementById('error-box');
  const toast = document.getElementById('toast');

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

      updateServerStatus(res.serverConnected);

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

  function updateServerStatus(online) {
    if (online) {
      statusDot.className = 'dot online';
      statusLabel.textContent = 'Sync Online';
    } else {
      statusDot.className = 'dot offline';
      statusLabel.textContent = 'Local Only';
    }
  }

  function showLockedView() {
    viewLocked.classList.remove('hidden');
    viewUnlocked.classList.add('hidden');
    btnLock.classList.add('hidden');
    modalSecret.classList.add('hidden');
    errorBox.classList.add('hidden');
  }

  function showUnlockedView() {
    viewLocked.classList.add('hidden');
    viewUnlocked.classList.remove('hidden');
    btnLock.classList.remove('hidden');
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
        } else {
          showError(res?.error || 'Failed to save secret');
        }
      } catch (err) {
        showError(err.message || 'Failed to save secret');
      }
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
