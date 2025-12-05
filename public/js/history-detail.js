(() => {
  const dom = {};

  function cacheDom() {
    dom.detailTime = document.getElementById('detailTime');
    dom.detailDuration = document.getElementById('detailDuration');
    dom.detailTokens = document.getElementById('detailTokens');
    dom.detailModel = document.getElementById('detailModel');
    dom.detailInput = document.getElementById('detailInput');
    dom.detailOutput = document.getElementById('detailOutput');
    dom.detailImageWrapper = document.getElementById('detailImageWrapper');
    dom.detailImage = document.getElementById('detailImage');
    dom.exportBtn = document.getElementById('exportBtn');
    dom.copyOutputBtn = document.getElementById('copyOutputBtn');
    dom.languageToggle = document.getElementById('languageToggle');
    dom.exportArea = document.getElementById('exportArea');
    dom.previewArea = document.getElementById('exportPreviewArea');
    dom.previewImage = document.getElementById('exportPreviewImage');
  }

  function formatTokens(detail) {
    const parts = [];
    if (detail.input_tokens != null) parts.push(`in:${detail.input_tokens}`);
    if (detail.output_tokens != null) parts.push(`out:${detail.output_tokens}`);
    if (detail.total_tokens != null) parts.push(`total:${detail.total_tokens}`);
    return parts.join(' / ') || '--';
  }

  function setPreview(src) {
    if (!dom.previewArea || !dom.previewImage) return;
    if (src) {
      dom.previewArea.classList.remove('hidden');
      dom.previewImage.src = src;
    } else {
      dom.previewArea.classList.add('hidden');
      dom.previewImage.src = '';
    }
  }

  function applyI18n() {
    i18n.applyTranslations();
    document.documentElement.setAttribute('lang', i18n.getLanguage());
  }

  async function loadDetail() {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    if (!id) {
      alert(i18n.t('common.requestFailed'));
      return;
    }
    try {
      const detail = await window.appCommon.authFetch(
        `/api/history/detail?id=${encodeURIComponent(id)}`,
        { headers: { Authorization: `Bearer ${window.appCommon.getToken()}` } },
        { requireAuth: true }
      );
      dom.detailTime.textContent = detail.created_at || '--';
      dom.detailDuration.textContent = detail.duration_ms != null ? `${detail.duration_ms}ms` : '--';
      dom.detailTokens.textContent = formatTokens(detail);
      dom.detailModel.textContent = detail.model_name || '--';
      dom.detailInput.textContent = detail.input_text || '';
      dom.detailOutput.innerHTML = detail.output_text ? marked.parse(detail.output_text) : '';
      if (detail.image_path) {
        dom.detailImageWrapper.classList.remove('hidden');
        dom.detailImage.src = detail.image_path;
      } else {
        dom.detailImageWrapper.classList.add('hidden');
        dom.detailImage.src = '';
      }
      setPreview(detail.image_path || '');
    } catch (err) {
      alert(err.message || i18n.t('common.requestFailed'));
    }
  }

  async function handleExport() {
    if (!dom.exportArea) return;
    try {
      dom.exportBtn.disabled = true;
      const canvas = await html2canvas(dom.exportArea, { useCORS: true, scale: 2, backgroundColor: '#ffffff' });
      const dataUrl = canvas.toDataURL('image/png');
       setPreview(dataUrl);
      const link = document.createElement('a');
      link.download = `History_${Date.now()}.png`;
      link.href = dataUrl;
      link.click();
    } catch (err) {
      alert(err.message || i18n.t('common.requestFailed'));
    } finally {
      dom.exportBtn.disabled = false;
    }
  }

  async function handleCopyOutput() {
    const text = dom.detailOutput?.innerText || '';
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      alert(i18n.t('history.copySuccess') || 'Copied');
    } catch (err) {
      alert(err.message || i18n.t('history.copyFailed'));
    }
  }

  function bindEvents() {
    dom.exportBtn?.addEventListener('click', handleExport);
    dom.copyOutputBtn?.addEventListener('click', handleCopyOutput);
    dom.languageToggle?.addEventListener('click', async () => {
      const nextLang = i18n.getLanguage() === 'zh' ? 'en' : 'zh';
      await i18n.setLanguage(nextLang);
      applyI18n();
    });
  }

  async function init() {
    cacheDom();
    const auth = window.appCommon.requireAuthOrRedirect();
    if (!auth) return;
    await window.appCommon.initI18n();
    applyI18n();
    bindEvents();
    await loadDetail();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
