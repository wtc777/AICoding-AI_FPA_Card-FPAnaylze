# Purpose

This project uses Codex CLI for local development.\
This document defines strict rules for patch safety, allowed
directories, internationalization requirements, and coding constraints
to ensure stable, predictable behavior.

Codex CLI must treat this file as the authoritative project guideline.

# ============================

# 1. Project Structure

# ============================

-   /pages → Route files (ALLOWED to modify)

-   /components → UI components (ALLOWED to modify)

-   /styles → Global styling (ALLOWED to modify)

-   /locales → i18n language packs (ALLOWED to modify)

-   /utils → Helper utilities (ALLOWED to modify)

-   /public → Static assets (DO NOT DELETE OR RENAME)

-   /data → Runtime data storage (DO NOT TOUCH)

-   /api → Backend API logic (modify ONLY when explicitly instructed)

-   package.json, next.config.js, tsconfig.json → MODIFY ONLY when
    explicitly instructed.

# ============================

# 2. Internationalization (i18n) Rules

# ============================

## 2.1 Primary rule

\*\*NO Chinese characters may appear in any source code files (.js,
.jsx, .ts, .tsx).\
All Chinese UI text must come from the language pack under
/locales/zh/\*.json.\*\*

## 2.2 Usage rule

-   Always use translation keys instead of hard-coded text:

    Example:

        {t("submit")}

-   If user provides Chinese UI text, write it ONLY into:

        /locales/zh/common.json

-   Never embed Chinese text directly inside any component code.

## 2.3 Language directory structure

    /locales
        /zh
            common.json
        /en
            common.json

# ============================

# 3. Patch Safety Rules (CRITICAL)

# ============================

-   Never delete files unless explicitly instructed.
-   Never modify or delete anything under:
    -   /public
    -   /data
-   Never recreate entire directories.
-   Avoid large-scale replacements or refactors unless explicitly
    required.
-   Modify only the minimal required code block.
-   If patch markers cannot be matched, Codex must request a more
    precise selection instead of failing.
-   Avoid patching files larger than \~300 lines unless a full rewrite
    is explicitly requested.
-   When unsure, ask for clarification.

# ============================

# 4. Frontend Coding Guidelines

# ============================

-   Use React function components only.
-   Use TailwindCSS for all styling.
-   NO inline CSS.
-   NO Chinese characters in code.
-   UI strings must use translation keys via `t()`.
-   New UI components must be placed in /components.
-   File names must follow lowercase-kebab-case.
-   Component names must be PascalCase.

# ============================

# 5. Backend Editing Guidelines

# ============================

-   Do NOT modify backend logic unless explicitly requested.
-   Do NOT modify activation code logic.
-   Do NOT modify authentication flow.
-   Do NOT change rate-limit logic.
-   Avoid touching any database-related logic unless explicitly
    requested.

# ============================

# 6. File Protection Rules

# ============================

Strictly protected: - /public → DO NOT delete or rewrite. - /data → DO
NOT modify or delete. - /api → MODIFY only when user explicitly requests
backend changes. - Config files (package.json, next.config.js,
tsconfig.json) → Only modify upon explicit instruction.

Allowed: - /pages - /components - /styles - /locales - /utils

# ============================

# 7. Apply Patch Behavior

# ============================

-   Only update the specific region the user wants.
-   Do not modify unrelated lines or perform implicit refactoring.
-   Always output stable, minimal patches.
-   Ask for clarification if the instruction conflicts with the rules
    defined here.
-   Follow the conventions above even if the user prompt is ambiguous.

# ============================

# 8. Build Instructions

# ============================

npm install\
npm run dev\
npm run build

# ============================

# 9. Final Notes

# ============================

-   When user instructions conflict with this document, Codex must
    default to SAFETY and request confirmation.
-   All generated code must be English-only.
-   All Chinese text must be stored exclusively inside /locales/zh JSON
    files.
