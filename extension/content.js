/**
 * VoidVault Minimal Content Script
 * Non-intrusive in-input badge & reactive autofill.
 */

(function () {
  'use strict';

  const extAPI = typeof browser !== 'undefined' ? browser : chrome;
  let activeDropdown = null;

  function findTargetInputs() {
    const passwordInputs = document.querySelectorAll('input[type="password"]:not([data-voidvault-attached])');
    passwordInputs.forEach(pwdInput => {
      pwdInput.setAttribute('data-voidvault-attached', 'true');
      attachBadge(pwdInput);
    });
  }

  function attachBadge(pwdInput) {
    const badge = document.createElement('div');
    badge.className = 'voidvault-badge';
    badge.title = 'VoidVault Autofill';

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M7 14c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3zm13.71-7.71l-1.42-1.42a1 1 0 0 0-1.41 0l-5.47 5.47A5.992 5.992 0 0 0 7 8c-3.31 0-6 2.69-6 6s2.69 6 6 6 6-2.69 6-6c0-.97-.24-1.89-.64-2.71l2.35-2.35 1.41 1.41a1 1 0 0 0 1.42 0l1.41-1.41 1.41 1.41a1 1 0 0 0 1.42 0l1.35-1.35a1 1 0 0 0 0-1.42z');
    svg.appendChild(path);
    badge.appendChild(svg);

    document.body.appendChild(badge);

    function updateBadgePosition() {
      if (!document.body.contains(pwdInput)) {
        badge.remove();
        return;
      }
      const rect = pwdInput.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) {
        badge.style.display = 'none';
        return;
      }
      badge.style.display = 'flex';
      badge.style.top = `${window.scrollY + rect.top + (rect.height - 20) / 2}px`;
      badge.style.left = `${window.scrollX + rect.right - 26}px`;
    }

    updateBadgePosition();
    window.addEventListener('resize', updateBadgePosition, { passive: true });
    window.addEventListener('scroll', updateBadgePosition, { passive: true });

    badge.addEventListener('click', async (e) => {
      e.stopPropagation();
      e.preventDefault();
      closeDropdown();

      try {
        const domain = window.location.hostname;
        const res = await extAPI.runtime.sendMessage({ action: 'AUTOFILL_QUERY', domain });

        if (!res || !res.isUnlocked) {
          alert('VoidVault is locked. Click the VoidVault extension icon to unlock.');
          return;
        }

        if (!res.matches || res.matches.length === 0) {
          alert(`No credentials found for ${domain}.`);
          return;
        }

        if (res.matches.length === 1) {
          injectCredentials(pwdInput, res.matches[0].username, res.matches[0].password);
        } else {
          showDropdown(badge, pwdInput, res.matches);
        }
      } catch (err) {
        console.error('[VoidVault] Autofill error:', err);
      }
    });
  }

  function showDropdown(badge, pwdInput, matches) {
    closeDropdown();

    const dd = document.createElement('div');
    dd.className = 'voidvault-dropdown';

    const header = document.createElement('div');
    header.className = 'voidvault-dropdown-header';
    header.textContent = 'Select Account to Fill';
    dd.appendChild(header);

    matches.forEach(m => {
      const item = document.createElement('div');
      item.className = 'voidvault-dropdown-item';

      const user = document.createElement('span');
      user.className = 'voidvault-dd-user';
      user.textContent = m.username || 'No username';

      const title = document.createElement('span');
      title.className = 'voidvault-dd-title';
      title.textContent = m.title || '';

      item.appendChild(user);
      item.appendChild(title);

      item.onclick = (e) => {
        e.stopPropagation();
        injectCredentials(pwdInput, m.username, m.password);
        closeDropdown();
      };

      dd.appendChild(item);
    });

    const badgeRect = badge.getBoundingClientRect();
    dd.style.top = `${window.scrollY + badgeRect.bottom + 4}px`;
    dd.style.left = `${Math.max(10, window.scrollX + badgeRect.right - 220)}px`;

    document.body.appendChild(dd);
    activeDropdown = dd;
  }

  function closeDropdown() {
    if (activeDropdown) {
      activeDropdown.remove();
      activeDropdown = null;
    }
  }

  document.addEventListener('click', () => closeDropdown());

  function injectCredentials(pwdInput, username, password) {
    if (!pwdInput) return;

    // Find associated username input in same form or preceding input
    let userInput = null;
    const form = pwdInput.closest('form');
    if (form) {
      userInput = form.querySelector('input[type="text"], input[type="email"], input[autocomplete*="username"], input[name*="user"], input[name*="login"], input[name*="email"]');
    }
    if (!userInput) {
      // Look at siblings before password input
      const allInputs = Array.from(document.querySelectorAll('input'));
      const idx = allInputs.indexOf(pwdInput);
      for (let i = idx - 1; i >= 0; i--) {
        const type = allInputs[i].type;
        if (type === 'text' || type === 'email') {
          userInput = allInputs[i];
          break;
        }
      }
    }

    if (userInput && username) {
      setInputValue(userInput, username);
      flashField(userInput);
    }

    if (pwdInput && password) {
      setInputValue(pwdInput, password);
      flashField(pwdInput);
    }
  }

  function setInputValue(input, value) {
    // Prototype descriptor setter to bypass React 16+ / Vue overrides
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (descriptor && descriptor.set) {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }

    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function flashField(input) {
    input.classList.add('voidvault-autofilled');
    setTimeout(() => {
      input.classList.remove('voidvault-autofilled');
    }, 1000);
  }

  // Listen for Fill Tab message from popup
  extAPI.runtime.onMessage.addListener((message) => {
    if (message?.action === 'AUTOFILL_FIELDS') {
      const pwd = document.querySelector('input[type="password"]');
      if (pwd) {
        injectCredentials(pwd, message.username, message.password);
      }
    }
  });

  // Initial scan & MutationObserver for dynamically rendered SPA forms
  findTargetInputs();
  const observer = new MutationObserver(() => findTargetInputs());
  observer.observe(document.body, { childList: true, subtree: true });
})();
