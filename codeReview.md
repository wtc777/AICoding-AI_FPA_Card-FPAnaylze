# Project Structure & Quality Review

## Key Structural Issues
- Frontend still served as multiple static HTMLs under `public/` (`index.html`, `parse.html`, `parse2.html`, `parse - ИББО.html`), not the required `/pages` + `/components` + `/styles` React/Tailwind structure; duplicated parse pages with non-ASCII naming.
- Backend is a single monolith `server.js` containing config, DB init/migrations, auth, services, and routing without modular separation (`api/services/config`), making maintenance and testing difficult.
- Runtime DB file `data/auth.db` kept in repo root with no migration scripts directory; `prompt.txt` referenced but missing.

## Code Quality
- `server.js` (300+ lines) mixes concerns (schema migration, auth, activation, chat, admin stats, external API calls) with no layering, shared error handling, or constants; no rate limiting/timeout/retry strategy for DashScope calls.
- Frontend logic is inline JS within each HTML, with repeated auth/upload/state/export code; no shared API client or state handling.
- Heavy inline `<style>` blocks across pages, violating Tailwind-only guideline.
- File naming inconsistent (`parse - ИББО.html`, `parse2.html`), unclear versioning and non-ASCII names.

## i18n Findings
- `locales/zh/common.json` is corrupted/invalid JSON; default language in `public/utils/i18n.js` is `zh`, so translation loading will fail at startup.
- Many Chinese strings hard-coded directly in `public/index.html`, `public/parse2.html`, and `parse - ИББО.html`, breaking the “Chinese only in /locales/zh JSON” rule.
- Language switching logic scattered; no centralized key validation or duplicate-key checks.

## API Design
- All routes defined inline in `server.js`; no route/controller/service split. Error messages are inline strings, not centralized constants; responses mix English literals and code strings.
- Frontend API calls are embedded in page scripts rather than a reusable client, leading to duplication and inconsistent error handling.

## Componentization & State
- Pages are monolithic; reusable UI (buttons, cards, modals, uploaders) not extracted into components.
- State is managed ad-hoc via `localStorage` in each page; no shared user/locale/credits context; props/state boundaries undefined.

## Recommendations (Actionable)
1) Rebuild structure per AGENTS: introduce `/src/pages`, `/components`, `/styles`, `/utils`, `/services`, `/api`; move HTML logic into React function components with Tailwind classes only.
2) Fix i18n first: recreate valid `locales/zh/common.json` aligned with `en/common.json`; remove Chinese hard-coding in all HTML; enforce `data-i18n`/`t()` usage; add a translation loader fallback.
3) Consolidate frontend: adopt shared API client (with token injection and error normalization), shared auth/locale context, and reusable components (UploadDropzone, ResultCard, UserMenu, Modal).
4) Trim public pages: choose a single parse experience and retire `parse2.html` and `parse - ИББО.html`; keep `index.html` as a redirect only.
5) Backend modularization: split `server.js` into config, DB, middleware (auth/roles), services (activation/chat/user/admin), and routers; add basic rate limiting/timeouts for DashScope; centralize error codes.
6) Assets/config: provide or ignore `prompt.txt` explicitly; relocate DB/migrations to a dedicated folder and keep `/data` out of versioned artifacts if possible.

## Suggested Target Structure
```
/src
  /pages (parse, login, profile, admin)
  /components (UploadDropzone, ResultCard, UserMenu, TrendChart, Modals)
  /styles (tailwind.config, globals)
  /utils (i18n, api-client, auth, file helpers)
  /services (auth, activation, analysis)
  /api (route modules)
/locales/en/common.json
/locales/zh/common.json
/public (static assets, prompts)
```
