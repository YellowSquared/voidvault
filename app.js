/**
 * VoidVault Website Client Controller
 * Pure vanilla JavaScript, zero dependencies.
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Simulator Toggle
  const btnClient = document.getElementById('btn-view-client');
  const btnAttacker = document.getElementById('btn-view-attacker');
  const panelClient = document.getElementById('panel-client');
  const panelAttacker = document.getElementById('panel-attacker');

  if (btnClient && btnAttacker && panelClient && panelAttacker) {
    btnClient.addEventListener('click', () => {
      btnClient.classList.add('active');
      btnAttacker.classList.remove('active');
      panelClient.classList.remove('hidden');
      panelAttacker.classList.add('hidden');
    });

    btnAttacker.addEventListener('click', () => {
      btnAttacker.classList.add('active');
      btnClient.classList.remove('active');
      panelAttacker.classList.remove('hidden');
      panelClient.classList.add('hidden');
    });
  }
});

// 2. Toggle password masking in mock simulator
const passwordsState = {};

function togglePasswordVisibility(id) {
  const el = document.getElementById(id);
  if (!el) return;

  const realSecrets = {
    'pwd-github': 'ghp_9K8w2xY7LmQ4vT1r0JpAa9BvC3dE5fG',
    'pwd-aws': 'wX9#mK$2vL@8qP&zT5!e7N*uR1^yA4(c',
    'pwd-proton': '4f8e-b9a2-7c3d-11e0-88af-99dc-71ba'
  };

  if (passwordsState[id]) {
    el.textContent = '••••••••••••••••••••••';
    passwordsState[id] = false;
  } else {
    el.textContent = realSecrets[id] || '••••••••';
    passwordsState[id] = true;
  }
}

// 3. Quickstart Tabs Switcher
function showTab(tabId) {
  const allTabs = document.querySelectorAll('.tab-content');
  const allBtns = document.querySelectorAll('.tab-btn');

  allTabs.forEach(tab => {
    tab.classList.remove('active');
  });

  allBtns.forEach(btn => {
    btn.classList.remove('active');
  });

  const targetTab = document.getElementById(tabId);
  if (targetTab) {
    targetTab.classList.add('active');
  }

  // Set active button
  const buttons = Array.from(allBtns);
  const matchedBtn = buttons.find(b => b.getAttribute('onclick')?.includes(tabId));
  if (matchedBtn) {
    matchedBtn.classList.add('active');
  }
}
