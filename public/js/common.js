(function () {
  function safeParseAuth(raw) {
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch (err) {
      console.warn('Invalid auth cache, clearing');
      localStorage.removeItem('momentsAuth');
      return null;
    }
  }

  function readAuth() {
    return safeParseAuth(localStorage.getItem('momentsAuth'));
  }

  function saveAuth(token, user) {
    console.log('[common] saveAuth');
    localStorage.setItem('momentsAuth', JSON.stringify({ token, user }));
  }

  function clearAuth() {
    console.log('[common] clearAuth');
    localStorage.removeItem('momentsAuth');
  }

  function getToken() {
    const auth = readAuth();
    return auth?.token || '';
  }

  function requireAuthOrRedirect() {
    const auth = readAuth();
    if (!auth || !auth.token) {
      window.location.href = '/login.html';
      return null;
    }
    return auth;
  }

  function buildHeaders(baseHeaders) {
    const headers = new Headers(baseHeaders || {});
    const token = getToken();
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    return headers;
  }

  async function authFetch(url, options = {}, { requireAuth = false } = {}) {
    if (requireAuth && !getToken()) {
      window.location.href = '/login.html';
      throw new Error('Unauthorized');
    }
    const headers = buildHeaders(options.headers);
    const res = await fetch(url, { ...options, headers });
    let data = null;
    try {
      data = await res.json();
    } catch (err) {
      /* ignore parse errors for non-JSON responses */
    }
    if (!res.ok) {
      const err = new Error(data?.error || 'Request failed');
      err.code = data?.code;
      throw err;
    }
    return data;
  }

  async function initI18n() {
    console.log('[common] initI18n start');
    await i18n.initTranslations();
    i18n.applyTranslations();
    document.documentElement.setAttribute('lang', i18n.getLanguage());
    console.log('[common] initI18n done ->', i18n.getLanguage());
  }

  window.appCommon = {
    readAuth,
    saveAuth,
    clearAuth,
    getToken,
    requireAuthOrRedirect,
    authFetch,
    initI18n
  };
})();
