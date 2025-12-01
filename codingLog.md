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
