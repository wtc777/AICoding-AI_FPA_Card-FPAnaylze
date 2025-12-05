(() => {
  const dom = {};
  let currentRole = '';

  function cacheDom() {
    dom.statUsers = document.getElementById('statUsers');
    dom.stat7 = document.getElementById('stat7');
    dom.stat30 = document.getElementById('stat30');
    dom.trendBox = document.getElementById('trendBox');
    dom.roleAlert = document.getElementById('roleAlert');
    dom.content = document.getElementById('content');
    dom.filterStatus = document.getElementById('filterStatus');
    dom.codeList = document.getElementById('codeList');
    dom.refreshCodes = document.getElementById('refreshCodes');
    dom.genCount = document.getElementById('genCount');
    dom.genUses = document.getElementById('genUses');
    dom.genBatch = document.getElementById('genBatch');
    dom.genExpire = document.getElementById('genExpire');
    dom.genBtn = document.getElementById('genBtn');
    dom.genResult = document.getElementById('genResult');
    dom.userPanel = document.getElementById('userPanel');
    dom.userSearch = document.getElementById('userSearch');
    dom.userList = document.getElementById('userList');
    dom.refreshUsers = document.getElementById('refreshUsers');
    dom.languageToggle = document.getElementById('languageToggle');
  }

  function updateLanguageToggle() {
    const nextLabel = i18n.getLanguage() === 'zh' ? i18n.t('common.switchToEnglish') : i18n.t('common.switchToChinese');
    dom.languageToggle.textContent = nextLabel;
  }

  function applyI18n() {
    i18n.applyTranslations();
    document.documentElement.setAttribute('lang', i18n.getLanguage());
    updateLanguageToggle();
  }

  function requireAuthRole(me) {
    if (!me || !me.role || !['admin', 'super_admin'].includes(me.role)) {
      dom.roleAlert.classList.remove('hidden');
      return false;
    }
    dom.roleAlert.classList.add('hidden');
    dom.content.classList.remove('hidden');
    if (me.role === 'super_admin') {
      dom.userPanel.classList.remove('hidden');
    }
    currentRole = me.role;
    return true;
  }

  function renderTrend(trend) {
    dom.trendBox.innerHTML = '';
    if (!trend || !trend.length) {
      dom.trendBox.innerHTML = `<div class="text-gray-400">${i18n.t('admin.noData')}</div>`;
      return;
    }
    trend.forEach((t) => {
      const div = document.createElement('div');
      div.textContent = `${t.day}: ${t.cnt}`;
      dom.trendBox.appendChild(div);
    });
  }

  async function loadStats() {
    const res = await window.appCommon.authFetch(
      '/api/admin/stats/overview',
      { headers: { Authorization: `Bearer ${window.appCommon.getToken()}` } },
      { requireAuth: true }
    );
    dom.statUsers.textContent = res.total_users ?? '--';
    dom.stat7.textContent = res.analyses_last7 ?? '--';
    dom.stat30.textContent = res.analyses_last30 ?? '--';
    renderTrend(res.trend);
  }

  function renderCodes(items) {
    dom.codeList.innerHTML = '';
    if (!items || !items.length) {
      dom.codeList.innerHTML = `<div class="text-gray-400">${i18n.t('admin.noCodes')}</div>`;
      return;
    }
    items.forEach((c) => {
      const div = document.createElement('div');
      div.className = 'rounded-lg border border-gray-100 bg-white/80 p-2';
      div.innerHTML = `
        <div class="flex justify-between"><span class="font-semibold">${c.code}</span><span class="text-xs text-gray-500">${c.status}</span></div>
        <div class="text-[11px] text-gray-500">${i18n.t('admin.cardUses')} ${c.total_uses} | ${i18n.t('admin.cardBatch')} ${c.batch_id || i18n.t('admin.none')} | ${i18n.t('admin.cardExpired')} ${c.expired_at || i18n.t('admin.none')}</div>
        <div class="text-[11px] text-gray-500">${i18n.t('admin.createdBy')} ${c.creator_phone || i18n.t('admin.none')}</div>
      `;
      dom.codeList.appendChild(div);
    });
  }

  async function loadCodes() {
    const params = new URLSearchParams();
    if (dom.filterStatus.value) params.append('status', dom.filterStatus.value);
    try {
      const data = await window.appCommon.authFetch(
        `/api/activation/list?${params.toString()}`,
        { headers: { Authorization: `Bearer ${window.appCommon.getToken()}` } },
        { requireAuth: true }
      );
      renderCodes(data.items || []);
    } catch (err) {
      dom.codeList.innerHTML = `<div class="text-rose-500 text-sm">${i18n.t('admin.loadFailed')}</div>`;
    }
  }

  async function generateCodes() {
    dom.genBtn.disabled = true;
    dom.genResult.textContent = i18n.t('parse.generating');
    const payload = {
      count: Number(dom.genCount.value || 0),
      uses_per_code: Number(dom.genUses.value || 0),
      batch_id: dom.genBatch.value || undefined,
      expired_at: dom.genExpire.value || undefined
    };
    try {
      const data = await window.appCommon.authFetch(
        '/api/activation/batch-generate',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        },
        { requireAuth: true }
      );
      dom.genResult.innerHTML = (data.codes || [])
        .map((c) => `<div class="font-mono text-xs">${c.code} (${c.total_uses})</div>`)
        .join('');
      await loadCodes();
    } catch (err) {
      dom.genResult.textContent = err.message || i18n.t('admin.actionFailed');
    } finally {
      dom.genBtn.disabled = false;
    }
  }

  function renderUsers(items, role) {
    dom.userList.innerHTML = '';
    if (!items || !items.length) {
      dom.userList.innerHTML = `<div class="text-gray-400">${i18n.t('admin.noUsers')}</div>`;
      return;
    }
    items.forEach((u) => {
      const div = document.createElement('div');
      div.className = 'rounded-lg border border-gray-100 bg-white/80 p-2 space-y-1';
      const roleBtn =
        u.role === 'admin'
          ? `<button data-role="normal" class="px-2 py-1 text-xs rounded border border-gray-200 hover:border-amber-200">${i18n.t('admin.removeAdmin')}</button>`
          : `<button data-role="admin" class="px-2 py-1 text-xs rounded border border-blue-200 text-blue-600 hover:border-blue-300">${i18n.t('admin.setAdmin')}</button>`;
      const resetBtn = `<button data-reset="true" class="px-2 py-1 text-xs rounded border border-rose-200 text-rose-600 hover:border-rose-300">${i18n.t('admin.resetPassword')}</button>`;
      div.innerHTML = `
        <div class="flex justify-between text-sm">
          <span class="font-semibold">${u.nickname || '--'} (${u.phone})</span>
          <span class="text-xs text-gray-500">${u.role}</span>
        </div>
        <div class="text-[11px] text-gray-500 flex justify-between">
          <span>credits: ${u.credits ?? '--'}</span>
          <span>${u.created_at || ''}</span>
        </div>
        <div class="flex justify-end gap-2">${role === 'super_admin' ? `${roleBtn}${resetBtn}` : ''}</div>
      `;
      if (role === 'super_admin') {
        const roleBtnEl = div.querySelector('button[data-role]');
        const resetBtnEl = div.querySelector('button[data-reset]');
        roleBtnEl?.addEventListener('click', async () => {
          roleBtnEl.disabled = true;
          try {
            await window.appCommon.authFetch(
              `/api/admin/users/${u.id}/set-role`,
              {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ role: roleBtnEl.dataset.role })
              },
              { requireAuth: true }
            );
            await loadUsers(role);
          } catch (err) {
            alert(err.message || i18n.t('admin.actionFailed'));
          } finally {
            roleBtnEl.disabled = false;
          }
        });
        resetBtnEl?.addEventListener('click', async () => {
          const ok = confirm(i18n.t('admin.resetPasswordConfirm'));
          if (!ok) return;
          resetBtnEl.disabled = true;
          try {
            await window.appCommon.authFetch(
              `/api/admin/users/${u.id}/reset-password`,
              { method: 'POST' },
              { requireAuth: true }
            );
            alert(i18n.t('admin.resetPasswordSuccess'));
          } catch (err) {
            alert(err.message || i18n.t('admin.actionFailed'));
          } finally {
            resetBtnEl.disabled = false;
          }
        });
      }
      dom.userList.appendChild(div);
    });
  }

  async function loadUsers(role) {
    if (role !== 'super_admin') return;
    const params = new URLSearchParams();
    if (dom.userSearch.value) params.append('q', dom.userSearch.value);
    try {
      const data = await window.appCommon.authFetch(
        `/api/admin/users?${params.toString()}`,
        { headers: { Authorization: `Bearer ${window.appCommon.getToken()}` } },
        { requireAuth: true }
      );
      renderUsers(data.items || [], role);
    } catch (err) {
      dom.userList.innerHTML = `<div class="text-rose-500 text-sm">${i18n.t('admin.loadFailed')}</div>`;
    }
  }

  function bindEvents() {
    console.log('[admin] bindEvents');
    dom.refreshCodes?.addEventListener('click', loadCodes);
    dom.filterStatus?.addEventListener('change', loadCodes);
    dom.genBtn?.addEventListener('click', generateCodes);
    dom.refreshUsers?.addEventListener('click', () => loadUsers(currentRole));
    dom.userSearch?.addEventListener('input', () => loadUsers(currentRole));
    dom.languageToggle?.addEventListener('click', async () => {
      const nextLang = i18n.getLanguage() === 'zh' ? 'en' : 'zh';
      await i18n.setLanguage(nextLang);
      applyI18n();
    });
  }

  async function init() {
    console.log('[admin] init start');
    if (!window.appCommon) {
      console.error('[admin] appCommon missing');
      return;
    }
    cacheDom();
    const auth = window.appCommon.requireAuthOrRedirect();
    if (!auth) return;
    await window.appCommon.initI18n();
    applyI18n();
    bindEvents();

    try {
      const me = await window.appCommon.authFetch('/auth/me', { headers: { Authorization: `Bearer ${window.appCommon.getToken()}` } });
      if (!requireAuthRole(me)) return;
      await loadStats();
      await loadCodes();
      await loadUsers(me.role);
    } catch (err) {
      window.appCommon.clearAuth();
      window.location.href = '/login.html';
    }
    console.log('[admin] init ready');
  }

  document.addEventListener('DOMContentLoaded', init);
})();
