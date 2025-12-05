(() => {
  const dom = {};
  let currentUser = null;

  function cacheDom() {
    dom.nicknameEl = document.getElementById('nickname');
    dom.phoneEl = document.getElementById('phone');
    dom.roleEl = document.getElementById('role');
    dom.creditsEl = document.getElementById('credits');
    dom.createdAtEl = document.getElementById('createdAt');
    dom.activationInput = document.getElementById('activationInput');
    dom.activationBtn = document.getElementById('activationBtn');
    dom.activationMsg = document.getElementById('activationMsg');
    dom.logoutBtn = document.getElementById('logoutBtn');
    dom.deleteBtn = document.getElementById('deleteBtn');
    dom.adminEntry = document.getElementById('adminEntry');
    dom.languageToggle = document.getElementById('languageToggle');
    dom.nicknameInput = document.getElementById('nicknameInput');
    dom.nicknameSaveBtn = document.getElementById('nicknameSaveBtn');
    dom.profileMsg = document.getElementById('profileMsg');
    dom.passwordCurrent = document.getElementById('passwordCurrent');
    dom.passwordNew = document.getElementById('passwordNew');
    dom.passwordConfirm = document.getElementById('passwordConfirm');
    dom.passwordSaveBtn = document.getElementById('passwordSaveBtn');
  }

  function maskPhone(phone) {
    if (!phone || phone.length < 7) return phone || '--';
    return `${phone.slice(0, 3)}****${phone.slice(-4)}`;
  }

  function roleLabel(role) {
    if (role === 'admin') return i18n.t('role.admin');
    if (role === 'super_admin') return i18n.t('role.super_admin');
    return i18n.t('role.normal');
  }

  function setUser(user) {
    currentUser = user;
    dom.nicknameEl.textContent = user.nickname || '--';
    dom.phoneEl.textContent = maskPhone(user.phone);
    dom.roleEl.textContent = roleLabel(user.role);
    dom.creditsEl.textContent = typeof user.credits === 'number' ? user.credits : '--';
    if (dom.createdAtEl) {
      const dateText = user.created_at ? new Date(user.created_at).toLocaleString() : '--';
      dom.createdAtEl.textContent = dateText;
    }
    if (dom.nicknameInput) {
      dom.nicknameInput.value = user.nickname || '';
    }
    if (dom.adminEntry) {
      if (user.role === 'admin' || user.role === 'super_admin') {
        dom.adminEntry.classList.remove('hidden');
      } else {
        dom.adminEntry.classList.add('hidden');
      }
    }
  }

  async function fetchMe() {
    const token = window.appCommon.getToken();
    if (!token) {
      window.location.href = '/login.html';
      return;
    }
    try {
      const user = await window.appCommon.authFetch('/auth/me', { headers: { Authorization: `Bearer ${token}` } });
      setUser(user);
    } catch (err) {
      window.appCommon.clearAuth();
      window.location.href = '/login.html';
    }
  }

  function updateLanguageToggle() {
    const nextLabel = i18n.getLanguage() === 'zh' ? i18n.t('common.switchToEnglish') : i18n.t('common.switchToChinese');
    dom.languageToggle.textContent = nextLabel;
  }

  function applyI18n() {
    i18n.applyTranslations();
    document.documentElement.setAttribute('lang', i18n.getLanguage());
    updateLanguageToggle();
    if (currentUser) setUser(currentUser);
  }

  function showProfileMessage(text, tone = 'info') {
    if (!dom.profileMsg) return;
    const toneMap = {
      info: 'text-gray-600',
      success: 'text-emerald-600',
      error: 'text-rose-600'
    };
    dom.profileMsg.textContent = text || '';
    dom.profileMsg.className = `text-sm ${toneMap[tone] || toneMap.info}`;
  }

  async function activateCode() {
    const code = (dom.activationInput.value || '').trim();
    if (!code) {
      dom.activationMsg.textContent = i18n.t('profile.activationRequired');
      dom.activationMsg.className = 'text-xs text-rose-500';
      return;
    }
    dom.activationBtn.disabled = true;
    dom.activationMsg.textContent = i18n.t('profile.activationPending');
    dom.activationMsg.className = 'text-xs text-gray-500';
    try {
      const data = await window.appCommon.authFetch(
        '/api/activation/use',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code })
        },
        { requireAuth: true }
      );
      const credits = data.credits ?? '--';
      dom.creditsEl.textContent = credits;
      dom.activationMsg.textContent = i18n.t('profile.activationSuccess', { credits });
      dom.activationMsg.className = 'text-xs text-green-600';
    } catch (err) {
      dom.activationMsg.textContent = err.message || i18n.t('profile.activationFailed');
      dom.activationMsg.className = 'text-xs text-rose-500';
    } finally {
      dom.activationBtn.disabled = false;
    }
  }

  async function updateNickname() {
    if (!dom.nicknameInput) return;
    const nickname = (dom.nicknameInput.value || '').trim();
    if (!nickname) {
      showProfileMessage(i18n.t('error.needNickname'), 'error');
      return;
    }
    try {
      dom.nicknameSaveBtn.disabled = true;
      await window.appCommon.authFetch(
        '/api/user/profile',
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ nickname })
        },
        { requireAuth: true }
      );
      showProfileMessage(i18n.t('profile.updateSuccess'), 'success');
      if (currentUser) {
        currentUser.nickname = nickname;
        setUser(currentUser);
      }
    } catch (err) {
      showProfileMessage(err.message || i18n.t('profile.updateFailed'), 'error');
    } finally {
      dom.nicknameSaveBtn.disabled = false;
    }
  }

  async function updatePassword() {
    if (!dom.passwordCurrent || !dom.passwordNew || !dom.passwordConfirm) return;
    const currentPassword = dom.passwordCurrent.value || '';
    const newPassword = dom.passwordNew.value || '';
    const confirmPassword = dom.passwordConfirm.value || '';
    if (!newPassword || newPassword.length < 6) {
      showProfileMessage(i18n.t('error.passwordTooShort'), 'error');
      return;
    }
    if (!/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
      showProfileMessage(i18n.t('error.passwordComplexity'), 'error');
      return;
    }
    if (newPassword !== confirmPassword) {
      showProfileMessage(i18n.t('error.passwordMismatch'), 'error');
      return;
    }
    try {
      dom.passwordSaveBtn.disabled = true;
      await window.appCommon.authFetch(
        '/api/user/change-password',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            old_password: currentPassword,
            new_password: newPassword,
            new_password_confirm: confirmPassword
          })
        },
        { requireAuth: true }
      );
      showProfileMessage(i18n.t('profile.updateSuccess'), 'success');
      dom.passwordCurrent.value = '';
      dom.passwordNew.value = '';
      dom.passwordConfirm.value = '';
      window.appCommon.clearAuth();
      setTimeout(() => {
        window.location.href = '/login.html';
      }, 500);
    } catch (err) {
      showProfileMessage(err.message || i18n.t('profile.updateFailed'), 'error');
    } finally {
      dom.passwordSaveBtn.disabled = false;
    }
  }

  function bindEvents() {
    dom.activationBtn.addEventListener('click', activateCode);

    dom.logoutBtn.addEventListener('click', () => {
      const ok = confirm(i18n.t('profile.logoutConfirm'));
      if (!ok) return;
      window.appCommon.clearAuth();
      window.location.href = '/login.html';
    });

    dom.deleteBtn.addEventListener('click', async () => {
      const keyword = i18n.t('profile.deleteConfirmKeyword');
      const text = prompt(i18n.t('profile.deleteConfirmPrompt', { keyword }));
      if (text !== keyword) return;
      try {
        const data = await window.appCommon.authFetch(
          '/api/profile/delete',
          { method: 'POST', headers: { 'Content-Type': 'application/json' } },
          { requireAuth: true }
        );
        if (!data?.success) throw new Error(i18n.t('profile.deleteFailed'));
        alert(i18n.t('profile.deleteSuccess'));
        window.appCommon.clearAuth();
        window.location.href = '/login.html';
      } catch (err) {
        alert(err.message || i18n.t('profile.deleteFailed'));
      }
    });

    dom.languageToggle.addEventListener('click', async () => {
      const nextLang = i18n.getLanguage() === 'zh' ? 'en' : 'zh';
      await i18n.setLanguage(nextLang);
      applyI18n();
    });
    dom.nicknameSaveBtn?.addEventListener('click', updateNickname);
    dom.passwordSaveBtn?.addEventListener('click', updatePassword);
  }

  async function init() {
    cacheDom();
    window.appCommon.requireAuthOrRedirect();
    await window.appCommon.initI18n();
    applyI18n();
    bindEvents();
    await fetchMe();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
