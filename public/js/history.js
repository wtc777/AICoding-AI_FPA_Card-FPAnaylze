(() => {
  const dom = {};
  let page = 1;
  let pageSize = 10;
  let total = 0;

  function cacheDom() {
    dom.startDate = document.getElementById('startDate');
    dom.endDate = document.getElementById('endDate');
    dom.keyword = document.getElementById('keyword');
    dom.filterBtn = document.getElementById('filterBtn');
    dom.resetBtn = document.getElementById('resetBtn');
    dom.historyList = document.getElementById('historyList');
    dom.historyEmpty = document.getElementById('historyEmpty');
    dom.prevPage = document.getElementById('prevPage');
    dom.nextPage = document.getElementById('nextPage');
    dom.pageInfo = document.getElementById('pageInfo');
    dom.languageToggle = document.getElementById('languageToggle');
    dom.detailModal = document.getElementById('detailModal');
    dom.closeDetail = document.getElementById('closeDetail');
    dom.detailTime = document.getElementById('detailTime');
    dom.detailDuration = document.getElementById('detailDuration');
    dom.detailTokens = document.getElementById('detailTokens');
    dom.detailModel = document.getElementById('detailModel');
    dom.detailInput = document.getElementById('detailInput');
    dom.detailOutput = document.getElementById('detailOutput');
    dom.detailImage = document.getElementById('detailImage');
    dom.detailImageWrapper = document.getElementById('detailImageWrapper');
  }

  function updatePager() {
    const totalPages = Math.ceil(total / pageSize) || 1;
    dom.pageInfo.textContent = `${page} / ${totalPages}`;
    dom.prevPage.disabled = page <= 1;
    dom.nextPage.disabled = page >= totalPages;
  }

  function renderList(items) {
    dom.historyList.innerHTML = '';
    if (!items || !items.length) {
      dom.historyEmpty.classList.remove('hidden');
      return;
    }
    dom.historyEmpty.classList.add('hidden');
    items.forEach((item) => {
      const card = document.createElement('div');
      card.className = 'rounded-2xl border border-gray-100 bg-white/80 p-4 shadow-sm space-y-2';
      const tokensText = [item.input_tokens, item.output_tokens, item.total_tokens]
        .filter((v) => v !== null && v !== undefined)
        .join('/');
      const thumb = item.image_path
        ? `<img src="${item.image_path}" alt="thumb" class="h-12 w-12 object-cover rounded-lg border border-gray-100" />`
        : '';
      card.innerHTML = `
        <div class="flex items-center justify-between text-sm text-gray-600">
          <span>${item.created_at || '--'}</span>
          <span>${item.duration_ms != null ? `${item.duration_ms}ms` : '--'}</span>
        </div>
        <div class="flex gap-3 items-start">
          ${thumb}
          <div class="flex-1 space-y-1">
            <div class="text-sm text-gray-800 overflow-hidden">${item.input_summary || ''}</div>
            <div class="text-sm text-gray-500 overflow-hidden">${item.output_summary || ''}</div>
            <div class="flex items-center justify-between text-xs text-gray-500">
              <span>${tokensText ? `tokens: ${tokensText}` : ''}</span>
              <div class="flex gap-2">
                <a class="text-blue-600 hover:text-blue-700 text-sm font-semibold" href="/history-detail.html?id=${encodeURIComponent(item.id)}">${i18n.t('history.viewDetail')}</a>
                <button data-id="${item.id}" class="text-rose-600 hover:text-rose-700 text-sm font-semibold">${i18n.t('history.delete')}</button>
              </div>
            </div>
          </div>
        </div>
      `;
      const delBtn = card.querySelector('button[data-id]');
      delBtn?.addEventListener('click', () => deleteItem(item.id));
      dom.historyList.appendChild(card);
    });
  }

  async function deleteItem(id) {
    const ok = confirm(i18n.t('history.deleteConfirm'));
    if (!ok) return;
    try {
      await window.appCommon.authFetch(
        `/api/history/${encodeURIComponent(id)}`,
        { method: 'DELETE' },
        { requireAuth: true }
      );
      await loadList(page);
    } catch (err) {
      alert(err.message || i18n.t('history.deleteFailed'));
    }
  }

  async function loadList(toPage = 1) {
    page = toPage;
    const params = new URLSearchParams();
    if (dom.startDate.value) params.append('startDate', dom.startDate.value);
    if (dom.endDate.value) params.append('endDate', dom.endDate.value);
    if (dom.keyword.value) params.append('keyword', dom.keyword.value.trim());
    params.append('page', page);
    params.append('pageSize', pageSize);
    try {
      const data = await window.appCommon.authFetch(
        `/api/history/list?${params.toString()}`,
        { headers: { Authorization: `Bearer ${window.appCommon.getToken()}` } },
        { requireAuth: true }
      );
      total = data.total || 0;
      pageSize = data.pageSize || pageSize;
      renderList(data.items || []);
      updatePager();
    } catch (err) {
      dom.historyList.innerHTML = `<div class="text-rose-500 text-sm">${err.message || i18n.t('common.requestFailed')}</div>`;
      dom.historyEmpty.classList.add('hidden');
    }
  }

  function formatTokens(detail) {
    const parts = [];
    if (detail.input_tokens != null) parts.push(`in:${detail.input_tokens}`);
    if (detail.output_tokens != null) parts.push(`out:${detail.output_tokens}`);
    if (detail.total_tokens != null) parts.push(`total:${detail.total_tokens}`);
    return parts.join(' / ') || '--';
  }

  function bindEvents() {
    dom.filterBtn?.addEventListener('click', () => loadList(1));
    dom.resetBtn?.addEventListener('click', () => {
      dom.startDate.value = '';
      dom.endDate.value = '';
      dom.keyword.value = '';
      loadList(1);
    });
    dom.prevPage?.addEventListener('click', () => page > 1 && loadList(page - 1));
    dom.nextPage?.addEventListener('click', () => loadList(page + 1));
    dom.languageToggle?.addEventListener('click', async () => {
      const nextLang = i18n.getLanguage() === 'zh' ? 'en' : 'zh';
      await i18n.setLanguage(nextLang);
      applyI18n();
    });
  }

  function applyI18n() {
    i18n.applyTranslations();
    document.documentElement.setAttribute('lang', i18n.getLanguage());
  }

  async function init() {
    cacheDom();
    const auth = window.appCommon.requireAuthOrRedirect();
    if (!auth) return;
    await window.appCommon.initI18n();
    applyI18n();
    bindEvents();
    await loadList(1);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
