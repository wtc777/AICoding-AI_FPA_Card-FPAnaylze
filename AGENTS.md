# AGENTS.md — Project Rules & Code Standards (Updated with Local Tailwind Build Only)

## 0. Purpose
This document defines the authoritative development rules for Codex CLI.  
Codex MUST treat this file as the highest‑priority rule set.

---

# 1. Project Structure Rules

### Allowed to Modify
- /pages  
- /components  
- /styles  
- /utils  
- /locales  
- /public/css  
- /public/js  
- /public HTML files (ONLY when explicitly authorized by the user)

### Restricted / Protected
- /public → **DO NOT delete or rename files**  
- /data → **DO NOT modify or delete**  
- /api → Modify ONLY when explicitly requested  
- package.json, config files → Modify only when authorized

---

# 2. Internationalization (i18n)

### Primary Rule  
**No Chinese characters allowed inside any code file (.js, .ts, .jsx, .tsx).**  
All UI Chinese text must reside in `/locales/zh/*.json`.

---

# 3. Patch Safety Rules
- Minimal, stable patches only  
- Never delete files unless explicitly instructed  
- Never refactor large files unless authorized  
- If patch markers mismatch → ask user  
- Codex must prioritize safety over assumptions  

---

# 4. Frontend Coding Guidelines

## 4.1 HTML Rules
- HTML = structure only  
- NO inline styles  
- NO inline scripts  
- NO inline events (`onclick=""`)  
- Scripts must use `defer`  

---

## 4.2 CSS Rules
- Styles belong in `/public/css/common.css` and per‑page CSS  
- No CSS in JS  
- Avoid selector depth > 3  

---

## 4.3 JS Rules
JS = behavior only.

Each page must include:

```js
document.addEventListener("DOMContentLoaded", initPage);
```

Event binding:

```js
document.querySelector("#btnSubmit")?.addEventListener("click", handler);
```

Forbidden:
- inline events  
- jQuery  

---

# 5. Backend Editing Guidelines
- Do NOT modify backend logic unless explicitly requested  

---

# 6. File Protection Rules
Protected:
- /public  
- /data  
- /api  

Allowed:
- /public/css  
- /public/js  
- /public/*.html (when authorized)  

---

# 7. Codex Apply‑Patch Behavior
- Minimal changes  
- No unrelated refactors  
- No patching build artifacts  
- Ask when unsafe  

---

# 8. Build Instructions
```
npm install
npm run build
```

---

# 9. Tailwind Local Build Standard (NO CDN ALLOWED)
This project **MUST use local Tailwind CLI build only**.  
No CDN, no JIT from cdn.tailwindcss.com, no external stylesheets.

## 9.1 Forbidden (strongly)
❌ Do NOT use:
```html
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://cdn.xxx/tailwind.min.css">
```

❌ Do NOT rely on CDN as a functional dependency.

---

## 9.2 Required Local Build Pipeline
Project must include:

- `tailwind.config.js`  
- `postcss.config.js`  
- `src/styles/tailwind.css`  
- Build output: `public/css/tailwind.build.css`

### tailwind.css:
```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

### package.json scripts:
```jsonc
{
  "scripts": {
    "build:css": "tailwindcss -c tailwind.config.js -i ./src/styles/tailwind.css -o ./public/css/tailwind.build.css --minify",
    "watch:css": "tailwindcss -c tailwind.config.js -i ./src/styles/tailwind.css -o ./public/css/tailwind.build.css --watch"
  }
}
```

### Required tailwind.config.js content:
```js
content: [
  "./public/**/*.html",
  "./public/**/*.js"
],
```

Codex MUST update content paths when adding new HTML/JS files.

---

## 9.3 HTML Linking Standard
All HTML pages MUST include:

```html
<link rel="stylesheet" href="/css/tailwind.build.css">
<link rel="stylesheet" href="/css/common.css">
```

And MUST NOT include:

- Tailwind CDN  
- External CSS URLs  
- Old local tailwind.min.css  

---

## 9.4 Arbitrary Value Classes (w-[880px], etc.)
Allowed, but Codex MUST ensure:
- Class names appear in scanned files, OR  
- Added to `safelist`:

```js
safelist: [
  "w-[880px]",
  "tracking-[0.2em]",
  "opacity-[0.03]",
  "from-[#4F7BFF]",
  "to-[#406D5FA]",
  "active:scale-[0.98]"
]
```

---

## 9.5 Codex responsibilities when modifying frontend
Codex MUST:
1. Never add CDN URLs  
2. Never modify tailwind.build.css directly  
3. Modify only source files (`tailwind.css`, HTML, JS)  
4. Remind user to execute:
```
npm run build:css
```

---

# 10. JS Library Loading Rules (marked, html2canvas)
- MUST use local static files:
```html
<script src="/js/libs/marked.min.js"></script>
<script src="/js/libs/html2canvas.min.js"></script>
```

- Codex MUST NOT use CDN versions.

---

# 11. Final Notes for Codex
- Local build = single source of truth  
- CDN is prohibited  
- Build artifacts cannot be patched  
- Ask for confirmation when unsure  

