const supportedLanguages = ['en', 'zh'];
const defaultLanguage = 'zh';

let translations = {};
let currentLanguage = defaultLanguage;
const cache = {};

function normalizeLang(lang) {
  if (typeof lang !== 'string') return defaultLanguage;
  const lower = lang.toLowerCase();
  return supportedLanguages.includes(lower) ? lower : defaultLanguage;
}

function interpolate(text, vars = {}) {
  if (typeof text !== 'string') return '';
  return text.replace(/\{\{\s*([^}]+)\s*\}\}/g, (_, key) => {
    const value = vars[key.trim()];
    return value === undefined || value === null ? '' : String(value);
  });
}

async function loadTranslations(lang) {
  const target = normalizeLang(lang);
  if (cache[target]) return cache[target];
  const res = await fetch(`/locales/${target}/common.json`);
  if (!res.ok) throw new Error(`Failed to load translations for ${target}`);
  const data = await res.json();
  cache[target] = data || {};
  return cache[target];
}

function t(key, vars = {}) {
  const value = translations[key];
  if (!value) return key;
  if (typeof value === 'string') return interpolate(value, vars);
  return key;
}

function applyTranslations(root = document) {
  const elements = root.querySelectorAll('[data-i18n]');
  elements.forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (!key) return;
    const attr = el.getAttribute('data-i18n-attr');
    const translated = t(key);
    if (translated === key) return;
    if (attr) {
      el.setAttribute(attr, translated);
    } else {
      el.textContent = translated;
    }
  });
}

async function setLanguage(lang) {
  currentLanguage = normalizeLang(lang);
  translations = await loadTranslations(currentLanguage);
  localStorage.setItem('momentsLang', currentLanguage);
  return currentLanguage;
}

async function initTranslations() {
  const stored = normalizeLang(localStorage.getItem('momentsLang'));
  await setLanguage(stored);
}

function getLanguage() {
  return currentLanguage;
}

window.i18n = {
  t,
  applyTranslations,
  setLanguage,
  getLanguage,
  initTranslations
};
