/**
 * VoidVault Minimal Cryptographic Subsystem
 * WebAuthn PRF (W3C Level 3) + WebCrypto HKDF + AES-256-GCM.
 */

const VoidVaultCrypto = (function () {
  'use strict';

  const DEFAULT_HKDF_SALT = new TextEncoder().encode('voidvault-prf-hkdf-salt-v2');
  const HKDF_INFO = new TextEncoder().encode('voidvault-aes256-gcm-key-v2');

  function bufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function bufferToBase64Url(buffer) {
    return bufferToBase64(buffer)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  function base64UrlToBuffer(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return base64ToBuffer(base64);
  }

  function bufferToHex(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function zeroBuffer(buffer) {
    if (buffer instanceof Uint8Array) {
      buffer.fill(0);
    }
  }

  async function deriveAesGcmKeyFromPrf(prfBytes) {
    if (!prfBytes || prfBytes.length !== 32) {
      throw new Error('PRF secret must be exactly 32 bytes');
    }

    const prfKeyMaterial = await crypto.subtle.importKey(
      'raw',
      prfBytes,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    return await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: DEFAULT_HKDF_SALT,
        info: HKDF_INFO
      },
      prfKeyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptVaultBlob(vaultData, aesKey) {
    if (!aesKey) {
      throw new Error('Missing active AES-256-GCM key for vault encryption');
    }

    const plaintext = typeof vaultData === 'string' ? vaultData : JSON.stringify(vaultData);
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      plaintextBytes
    );

    return {
      version: 2,
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertextBuffer),
      updatedAt: new Date().toISOString()
    };
  }

  async function decryptVaultBlob(encryptedBlob, aesKey) {
    if (!aesKey) {
      throw new Error('Missing active AES-256-GCM key for vault decryption');
    }
    if (!encryptedBlob || !encryptedBlob.iv || !encryptedBlob.ciphertext) {
      throw new Error('Invalid encrypted vault blob structure');
    }

    const iv = base64ToBuffer(encryptedBlob.iv);
    const ciphertext = base64ToBuffer(encryptedBlob.ciphertext);

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ciphertext
    );

    const decryptedText = new TextDecoder().decode(decryptedBuffer);
    try {
      return JSON.parse(decryptedText);
    } catch {
      return decryptedText;
    }
  }

  function resolveRpId() {
    if (typeof window !== 'undefined' && window.location) {
      if (window.location.protocol === 'moz-extension:' || window.location.protocol === 'chrome-extension:') {
        return 'localhost';
      }
      if (window.location.hostname && window.location.hostname !== '') {
        return window.location.hostname;
      }
    }
    return 'localhost';
  }

  async function registerWithWebAuthnPrf({ username = 'voidvault_user', displayName = 'VoidVault User' } = {}) {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      throw new Error('WebAuthn is not supported in this environment');
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const rpId = resolveRpId();

    const credential = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'VoidVault Minimal', id: rpId },
        user: { id: userId, name: username, displayName },
        challenge,
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' }
        ],
        authenticatorSelection: {
          userVerification: 'preferred',
          residentKey: 'preferred',
          requireResidentKey: false
        },
        timeout: 60000,
        extensions: { prf: {} }
      }
    });

    return {
      credentialId: bufferToBase64Url(credential.rawId),
      rawId: credential.rawId
    };
  }

  async function authenticateWithWebAuthnPrf({ credentialId = null } = {}) {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      throw new Error('WebAuthn is not supported in this environment');
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const rpId = resolveRpId();

    const getOptions = {
      publicKey: {
        challenge,
        rpId,
        ...(credentialId
          ? {
              allowCredentials: [
                {
                  id: base64UrlToBuffer(credentialId),
                  type: 'public-key'
                }
              ]
            }
          : {}),
        userVerification: 'preferred',
        timeout: 60000,
        extensions: {
          prf: {
            eval: { first: DEFAULT_HKDF_SALT }
          }
        }
      }
    };

    const assertion = await navigator.credentials.get(getOptions);
    const clientExtensions = assertion.getClientExtensionResults();

    let prfOutput = null;
    if (clientExtensions?.prf?.results?.first) {
      prfOutput = new Uint8Array(clientExtensions.prf.results.first);
    } else if (clientExtensions?.hmacGetSecret?.output1) {
      prfOutput = new Uint8Array(clientExtensions.hmacGetSecret.output1);
    }

    if (!prfOutput || prfOutput.length !== 32) {
      throw new Error('Authenticator did not return a 32-byte PRF extension secret.');
    }

    return {
      prfOutput,
      credentialId: bufferToBase64Url(assertion.rawId)
    };
  }

  async function deriveSimulatedPrf(passphrase = 'voidvault-dev-simulated-key') {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: DEFAULT_HKDF_SALT,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return new Uint8Array(bits);
  }

  return {
    bufferToBase64,
    base64ToBuffer,
    bufferToBase64Url,
    base64UrlToBuffer,
    bufferToHex,
    zeroBuffer,
    deriveAesGcmKeyFromPrf,
    encryptVaultBlob,
    decryptVaultBlob,
    registerWithWebAuthnPrf,
    authenticateWithWebAuthnPrf,
    deriveSimulatedPrf
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = VoidVaultCrypto;
}
