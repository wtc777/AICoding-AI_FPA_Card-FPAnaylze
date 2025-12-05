# Moments Optimizer

基于 DashScope（通义千问）的朋友圈文案/卡片优化小工具。后端使用 Express + SQLite 管理用户、额度与激活码，前端是静态页面（Tailwind UI）支持图片识别、文案润色以及管理后台。

## 快速开始
- 环境：Node.js 18+，已内置 `node-fetch` 依赖；本地 SQLite 数据库存放于 `data/auth.db`。
- 安装依赖：`npm install`
- 配置环境变量：复制 `.env.example` 为 `.env`，至少填写 `DASHSCOPE_API_KEY`；可按需覆盖 `TEXT_MODEL`、`VISION_MODEL`、`PORT`、`AUTH_SECRET`。
- 运行服务：`npm run start`（默认端口 3021）。前端静态页直接通过 `http://localhost:3021/*.html` 访问。

## 主要功能
- 用户体系：手机号 + 密码注册/登录，JWT 鉴权（`Authorization: Bearer <token>`）。首次注册默认获得 5 次额度。
- 额度管理：每次文本/图文分析消耗 1 次额度；可通过激活码追加额度。
- 激活码：普通用户可“使用”激活码；管理员/超管可批量生成、查看激活码及使用日志。
- 文案优化：`/api/chat/text` 纯文本；`/api/chat/image` 支持上传图片（Base64）+ 文案，先用视觉模型抽取要点，再用文本模型生成润色结果。
- 统计看板：管理员可查看全站概览、用户趋势；超管可下发/收回管理员角色。

## 前端页面
- `public/login.html`：注册/登录，保存 token 至浏览器本地。
- `public/parse.html`：主功能页，上传朋友圈图片并附加描述后获取优化文案，可导出图片。
- `public/profile.html`：查看额度、使用激活码、注销账号。
- `public/admin.html`：激活码批量生成、列表、使用日志及统计。
- `public/index.html`：重定向到 `parse.html`；`parse2.html` 为旧版界面备份。

## API 摘要
- 认证：`POST /auth/register`，`POST /auth/login`，`GET /auth/me`；`POST /auth/init-super-admin` 初始化唯一超管；`POST /api/profile/delete` 注销账号。
- 激活码：`POST /api/activation/use`（用户使用）；`POST /api/activation/batch-generate`、`GET /api/activation/list`、`GET /api/activation/:id/logs`（管理员/超管）。
- 分析：`POST /api/chat/text`，`POST /api/chat/image`（均需登录且扣减额度）。
- 管理/统计：`GET /api/admin/stats/overview`，`GET /api/admin/users`，`GET /api/admin/users/:id/stats`，`POST /api/admin/users/:id/set-role`（仅超管可分配角色）。

## 配置与数据
- 提示词：根目录 `prompt.txt` 为通用提示；场景化提示存放在 `public/prompts/`，如 `MOMENT_SCENARIO.txt`、`CARD_SCENARIO.txt`，可按需编辑。
- 数据库：`data/auth.db` 自动创建；如需重置可删除该文件（会丢失全部账号与激活码）。
- Token：默认 7 天有效，密钥由 `AUTH_SECRET` 控制（未配置时使用开发默认值，生产环境务必覆盖）。

## 常见访问入口
- 登录/注册：`http://localhost:3021/login.html`
- 文案优化：`http://localhost:3021/parse.html`
- 个人中心：`http://localhost:3021/profile.html`
- 管理后台：`http://localhost:3021/admin.html`（需管理员/超管角色）
