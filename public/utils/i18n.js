(() => {
  const STORAGE_KEY = 'cardInsightLang';
  const CACHE = {};

  async function loadTranslations(lang) {
    const safeLang = lang || 'zh';
    if (CACHE[safeLang]) return CACHE[safeLang];
    try {
      const res = await fetch(`/locales/${safeLang}/common.json`);
      if (!res.ok) throw new Error(`Load i18n failed: ${res.status}`);
      const data = await res.json();
      CACHE[safeLang] = data || {};
    } catch (err) {
      console.warn('i18n load error', err);
      CACHE[safeLang] = {};
    }
    return CACHE[safeLang];
  }

  function getLang() {
    return localStorage.getItem(STORAGE_KEY) || 'zh';
  }

  function setLang(lang) {
    localStorage.setItem(STORAGE_KEY, lang || 'zh');
  }

  function resolve(dict, key) {
    return key.split('.').reduce((acc, part) => (acc && acc[part] !== undefined ? acc[part] : undefined), dict);
  }

  function applyTranslations(dict, entries) {
    if (!dict || !entries) return;
    entries.forEach((item) => {
      const el = document.querySelector(item.selector);
      if (!el) return;
      const value = resolve(dict, item.key);
      if (value === undefined) return;
      if (item.attr === 'placeholder') {
        el.setAttribute('placeholder', value);
      } else if (item.attr === 'html') {
        el.innerHTML = value;
      } else {
        el.textContent = value;
      }
    });
  }

  window.i18n = {
    loadTranslations,
    applyTranslations,
    getLang,
    setLang
  };
})();
