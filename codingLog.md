### 2025-11-29 22:58 - Initial DashScope chat H5 scaffold
- Files: `server.js`, `package.json`, `public/index.html`, `.env.example`
- Added Express server bootstrap with dotenv-based configuration.
- Wired DashScope base URL and model defaults to environment variables.
- Implemented text chat endpoint mapping to OpenAI-compatible completions.
- Implemented vision chat endpoint handling mixed text and base64 image content.
- Added shared DashScope request helper with basic error propagation.
- Enabled static hosting for frontend assets from the public directory.
- Increased JSON body limit to support image payloads.
- Built H5 interface with dual text/vision mode selectors.
- Added image upload preview and auto-switch to vision mode.
- Integrated Markdown rendering for assistant messages.
- Hooked frontend fetch flows to text and vision APIs with error feedback.
- TODO: Add automated tests and streaming response handling.

### 2025-11-29 22:59 - Align port configuration to 3020
- Files: `server.js`, `.env.example`
- Updated default server port fallback to 3020.
- Synced .env example port to 3020 for consistency.
- Ensured port change keeps environment override via PORT intact.
- Maintained existing DashScope configuration flow.
- Confirmed no other logic changes alongside port tweak.
- Frontend static serving remains unchanged.
- API routes unaffected by port configuration shift.
- No dependency updates required for port adjustment.
- Body size limits unchanged after port update.
- CORS and static assets configuration retained.
- Logging behavior unchanged with new port.
- TODO: Document run command reflecting port 3020.

### 2025-11-29 23:03 - Add Windows start script
- Files: `start.bat`
- Added Windows batch script to install deps if missing and start server.
- Script echoes target port using PORT env or defaults to 3020 via npm start.
- Keeps environment isolation with setlocal/endlocal.
- No code changes to backend or frontend logic.
- Supports first-time setup convenience on Windows.
- Leaves existing npm scripts unchanged.
- Does not modify package versions or dependencies.
- No change to API routes or payload handling.
- Maintains compatibility with .env configuration.
- Introduces basic install guard checking node_modules presence.
- TODO: Add PowerShell variant if needed.

### 2025-11-29 23:07 - Fix vision payload format
- Files: `server.js`
- Updated text endpoint to use structured content parts for consistency.
- Corrected vision endpoint to wrap image_url in url object per OpenAI schema.
- Ensured mixed content sends text and image together after upload.
- Maintained DashScope request helper without additional changes.
- No adjustments to frontend fetch logic required.
- Preserved error handling and response shape.
- Body size limits unchanged at 10mb.
- Port configuration remains at 3020 fallback.
- Static asset serving unaffected by payload change.
- Dependency versions unchanged.
- TODO: Add integration test for vision payload validation.

### 2025-11-29 23:21 - Add two-step vision flow with UI step status
- Files: `server.js`, `public/index.html`
- Implemented two-phase vision handling: image analysis then text reasoning with combined prompt.
- Added response normalization to handle content arrays and strings from DashScope.
- Vision endpoint now returns imageAnalysis alongside final reply.
- Text endpoint uses structured content array for compatibility.
- Frontend now shows step-by-step status badges for text and vision flows.
- Vision statuses include validation, vision call, combine, and text call phases.
- Displays image analysis detail in status panel when available.
- UI gains step styling for active/done/error states.
- Maintained existing Markdown chat rendering and mode toggles.
- No dependency changes required for the new flow.
- TODO: Add automated tests for two-step pipeline and frontend status rendering.

### 2025-11-29 23:26 - Integrate prompt file and reorder UI flow with export
- Files: `server.js`, `public/index.html`, `prompt.txt`
- Added prompt reader to inject external prompt.txt into every model call.
- Ensured both text and vision pipelines prepend prompt content dynamically.
- Added default prompt.txt with concise multimodal guidance.
- Reordered UI to match Text Input → Image Upload → Start → Steps → Result → Export.
- Renamed send action to “开始解析” and added visual order hint.
- Inserted result export-to-image button using html2canvas.
- Kept Markdown rendering for results and preserved mode toggles.
- Added results header styling and refined composer borders.
- Vision flow still surfaces step states and image analysis feedback.
- No backend dependency changes; frontend pulls html2canvas via CDN.
- PORT and API configs remain unchanged.
- TODO: Add validation for missing prompt file and more detailed export feedback.

### 2025-11-29 23:31 - Clear results before parse and include user assets in export
- Files: `public/index.html`
- Added result reset on each parse to clear previous chat and steps.
- Wrapped result area to export combined content (user text, image, replies).
- Added user image bubble so uploads appear in results/export.
- Updated export target to capture header + chat with html2canvas.
- Kept step statuses while clearing per new run requirement.
- Maintained existing parsing flow and mode toggles.
- No backend changes required for reset/export update.
- Export now includes uploaded image when present.
- UI still orders input, upload, start, status, result, export.
- TODO: Add user metadata overlay in export for clarity.

### 2025-11-29 23:34 - Allow empty text when image provided
- Files: `server.js`, `public/index.html`
- Relaxed image endpoint validation to accept requests with only image or text.
- Added frontend guard: must have text or image; text mode still requires text.
- Kept image mode compatible with empty text alongside uploaded image.
- Maintained existing two-step vision flow and prompt injection.
- Validation messages updated for new start conditions.
- No changes to model routing or prompt content.
- Export and step status behaviors unchanged.
- TODO: Add tests for image-only requests and frontend validation flow.

### 2025-11-29 23:39 - Strengthen card extraction instructions
- Files: `server.js`
- Updated vision system and user prompts to emphasize card recognition.
- Added explicit targets: color limited to 红/蓝/黄/绿, row (第几排), score, and content.
- Kept fallback to mark unknown fields when missing in image.
- Maintained two-step vision-to-text pipeline and prompt injection.
- No changes to text endpoint or combined prompt assembly.
- Dependencies and configuration remain unchanged.
- TODO: Add sample image tests for card extraction accuracy.

### 2025-12-01 16:40 - Replace frontend with AI 解析助手 UI
- Files: `public/index.html`
- Swapped legacy chat page for new AI 解析助手 single-page UI (Tailwind CDN) with upload, text input, markdown render, and export-to-image.
- Hooked callApi to existing `/api/chat/text` and `/api/chat/image` endpoints, converting uploaded images to base64 before POST.
- Added html2canvas/marked integrations and status badges; includes virtual smoke log to confirm wiring without backend calls.
- Export panel mirrors parsed markdown with preview image and user text; kept backend/server structure untouched.

### 2025-12-01 16:55 - Add toggle for image analysis display
- Files: `public/index.html`
- Added a checkbox in the result header to show/hide the image analysis text, defaulting to on.
- Respect toggle state when rendering results and instantly hide analysis when unchecked.
- Kept API wiring, markdown render, and export behavior unchanged.

### 2025-12-01 17:05 - Move export button and default-hide analysis
- Files: `public/index.html`
- Moved “保存分析报告” button below the result card and styled it to match the primary “开始 AI 解析” gradient button.
- Set “显示图像解析” toggle to default off; image analysis text only appears when enabled.
- Kept all API integrations, export flow, and markdown rendering untouched.

### 2025-12-01 17:25 - Disable parse button during processing
- Files: `public/index.html`
- Added runtime override to show “解析中...” with spinner and disable the “开始 AI 解析” button while processing, restoring label/state after completion.
- Processing modal still shows; button is now protected from re-click during analysis.

### 2025-12-01 17:40 - Add scenario selector and prompt injection
- Files: `public/index.html`
- Added a scenario dropdown above Step 1 with descriptions for “性格色彩卡牌分析” and “朋友圈文案优化”.
- Prepends selected scenario prompt to user text and passes scenario in payload to existing API calls (text/image); exports still show user’s original text.
- Updated front-end API payloads to include scenario key while keeping existing endpoints unchanged.

### 2025-12-01 18:10 - Rebuild frontend with prompt loader and scenario dropdown
- Files: `public/index.html`, `public/prompt.txt`
- Recreated frontend entry to avoid encoding issues; added scenario selector and prompt loader that fetches `prompt.txt` sections `[CARD_SCENARIO]` / `[MOMENT_SCENARIO]`.
- Sends combined prompt + user text with `scenario` to existing `/api/chat/text` and `/api/chat/image`; keeps export showing user’s raw text.
- Preserved spinner/disabled state during parsing, processing modal, markdown render, image export, and image analysis toggle.

### 2025-12-01 18:22 - Load prompts from per-scenario files
- Files: `public/index.html`
- Updated prompt loader to fetch per-scenario files in `public/prompts` (`CARD_SCENARIO.txt`, `MOMENT_SCENARIO.txt`) with caching.
- Maintained scenario dropdown and payload shape (`scenario` + combined prompt + user text) to existing endpoints.

### 2025-12-01 18:35 - Recreate frontend from clean source
- Files: `public/index.html`
- Rebuilt index to avoid prior corruption, keeping scenario dropdown and loading prompts from `/prompts/CARD_SCENARIO.txt` and `/prompts/MOMENT_SCENARIO.txt` per selection.
- Ensures selected prompt text prepends user input, sends `scenario` with payload, and preserves existing UI behaviors (spinner/disable during parse, modal, export, image toggle).

### 2025-12-01 18:50 - Backend loads scenario-specific prompts
- Files: `server.js`
- Added scenario prompt loader reading `/public/prompts/CARD_SCENARIO.txt` or `/public/prompts/MOMENT_SCENARIO.txt` based on `scenario`; falls back to `prompt.txt`.
- Text/image endpoints now use scenario prompt instead of always `prompt.txt`, preserving existing model calls and payload shapes.

### 2025-12-01 19:00 - Ignore prompt secrets and add examples
- Files: `.gitignore`, `public/prompts/CARD_SCENARIO.example.txt`, `public/prompts/MOMENT_SCENARIO.example.txt`
- Gitignore now excludes real prompt files (`public/prompts/CARD_SCENARIO.txt`, `public/prompts/MOMENT_SCENARIO.txt`); added example placeholders for both scenarios.

### 2025-12-02 14:40 - Split auth and parse pages with login gating
- Files: `public/login.html`, `public/parse.html`, `public/index.html`
- Created standalone login/register page with tab toggle and 11-digit phone validation.
- Added register flow requiring phone, nickname, password (>=6) with inline feedback.
- Persisted auth info to `localStorage` and redirect to parse page on success.
- Built dedicated parse page for upload/analyze/export; removed auth UI from flow.
- Added auth guard on parse page; missing auth redirects to login; logout clears storage.
- Kept glassmorphism styling, gradients, and original upload/result layout.
- Maintained prompt loading, text composition, and API calls for image/text scenarios.
- Preserved processing modal, disabled state, and spinner during analysis.
- Kept export-to-image pipeline using html2canvas and hidden export area.
- Added user info display on parse page header with logout control.
- Redirected old `index.html` to parse page to avoid mixed auth/parse UI.
- Ensured phone/password remain client-side only (no backend requests for auth).

### 2025-12-02 15:00 - Hook auth to SQLite backend
- Files: `server.js`, `public/login.html`, `public/parse.html`, `package.json`
- Added sqlite3 dependency and initialized `data/auth.db` with users table.
- Implemented password hashing (scrypt) and HMAC-based token issuing/verification.
- Replaced file-based mock storage with persistent SQLite queries.
- Added register/login/me endpoints to return token + user info; secured me with token check.
- Added express auth middleware to validate Bearer tokens for user fetch.
- Login/register front-end now posts to backend, stores token/user from response.
- Parse page attaches Authorization headers and verifies session via `/auth/me` on load.
- Logout clears token storage and redirects to login for reuse.
- Kept existing prompt/chat/image flows unchanged, only gated by auth token.
- Ensured data directory auto-created for SQLite file and table bootstrap.
- Updated error handling with localized messages for auth flows.
- Package dependencies now include sqlite3 for persistence.

### 2025-12-02 15:15 - Simplify login/register layout
- Files: `public/login.html`
- Removed “更安全的内容管理” side info block to focus solely on auth forms.
- Preserved login/register tab toggle, validation, and backend calls.

### 2025-12-02 16:00 - Add roles, credits, activation codes, admin stats
- Files: `server.js`, `package.json`, `public/login.html`, `public/parse.html`
- Switched auth storage to SQLite schema with role/credits columns and migration helpers.
- Implemented scrypt password hashing, HMAC tokens carrying role, and role guard middleware.
- Added super admin initializer endpoint to bootstrap the first super_admin safely.
- Created activation codes/logs tables, batch generation APIs, and user-side activation use flow.
- Linked activation to credits updates and exposed admin activation list/logs endpoints.
- Introduced analysis logs with per-call credit deduction and insufficient credits handling.
- Guarded text/image parse APIs with auth, credit checks, and logging plus remaining credits return.
- Added admin stats (overview, per-user) and user list/role assignment (super_admin only) APIs.
- Updated front-end parse page to show user info, credits, and activation code usage UI.
- Login/register now return role/credits and rely on backend auth instead of mock storage.
- Maintained front-end analyze/export UI while surfacing credit exhaustion errors.
- Added sqlite3 dependency for persistence and ensured data directory/table bootstrap.

### 2025-12-02 16:20 - Fix schema migration column name bug
- Files: `server.js`
- Corrected migration helper to append column name when adding missing columns, preventing duplicate “TEXT” column errors.
- Restart server to rerun migration and add missing role/credits/updated_at columns to existing users table.

### 2025-12-02 17:10 - Add admin dashboard and profile center UI
- Files: `public/admin.html`, `public/profile.html`, `public/parse.html`
- Built admin dashboard (role-gated) for stats overview, activation code batch generation/listing, and super admin user role management.
- Added personal center page showing masked phone, role, credits, activation input, logout, and account deletion flow.
- Parse page now links to personal center and conditionally shows admin entry for admin/super_admin users.
- Preserved mobile-friendly layout with glass cards and button states; activation inputs show inline feedback.

### 2025-12-03 08:20 - Render parse result as Markdown
- Files: `public/parse.html`, `codingLog.md`
- Rendered analysis output with marked to preserve markdown styling.
- Added raw text container beneath results for original content viewing.
- Wired DOM references for raw text, raw section, and copy button.
- Populated raw text area with API markdown payload when available.
- Hid raw section automatically when no markdown is returned.
- Attached clipboard handler to copy the untouched markdown text.
- Disabled copy button when missing content to prevent empty copies.
- Kept placeholder/result visibility logic intact after render.
- Left export flow untouched while leveraging existing markdown payload.
- Ensured image analysis text uses a colon separator for readability.
- Retained analysis toggle behavior with explicit visibility control.
- Preserved clipboard helper reuse for new copy action.
- Guarded raw state reset alongside file reset and new render states.

### 2025-12-03 08:55 - Bump server port to 3021
- Files: `.env`, `.env.example`, `server.js`, `start.bat`
- Updated default PORT fallback from 3020 to 3021 in server bootstrap.
- Refreshed .env example to guide new configurations to 3021.
- Adjusted local .env to listen on 3021 for runtime consistency.
- Synced start script message to reflect the new default port.
- Kept existing Express setup and middleware unchanged.
- Left API endpoints and routing logic untouched.
- Maintained dependency list and scripts as-is.
- No database or schema changes introduced.
- Environment variable names remain stable for deployments.
- Start workflow still installs deps when missing node_modules.
- Manual verification required: run `npm start` and confirm bind to 3021.
- No automated tests executed for this configuration tweak.

### 2025-12-03 09:05 - Ignore local data directory
- Files: `.gitignore`, `codingLog.md`
- Added ignore rule for `data/` to avoid committing SQLite artifacts.
- Clarified comment describing local persistent data.
- Prevented deployments from overwriting runtime data with repo commits.
- Kept example prompt ignores unchanged.
- No code or API behavior changes.
- No database schema migrations performed.
- No dependency updates required.
- Start scripts remain unchanged.
- Server port remains 3021 from prior update.
- Frontend assets untouched.
- Tests not run (config-only change).
- Deployment note: ensure target environments create/protect their own data directory.
