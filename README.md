# Personality Color Card Analysis (AI 卡牌大师)

本项目基于现有架构改造为「性格色彩卡牌分析」应用，前端静态页面配合 Node/Express + sqlite。支持图片/文本解牌、激活码管理、多语言（默认中文）、个人资料修改、管理员功能。

## 目录结构
- `public/` 静态前端页面（解析、登录、个人中心、管理等）
- `public/prompts/CARD_SCENARIO.txt` 解牌提示词
- `public/utils/i18n.js` 前端多语言加载
- `locales/` 中英翻译
- `server.js` Express 服务与 API

## 运行
```bash
npm install
npm start          # 默认端口 3020（可用环境变量 PORT 覆盖）
```
或运行 `start.bat`（自动安装依赖并启动）。

## 主要功能
- 解牌：上传卡牌图片/文本，调用 `/api/chat/image` 或 `/api/chat/text`，使用 `CARD_SCENARIO.txt` 提示词。
- 多语言：默认中文，可在个人中心/管理页切换 EN。翻译来自 `locales/zh|en/common.json`。
- 账户：登录/注册、个人中心查看/充值（激活码）、修改昵称、修改密码（需旧密码）。
- 管理（admin/super_admin）：激活码生成/列表、用户列表、角色调整（super_admin），重置用户密码为 123456。
- 超级管理员密码重置：前端确认提示 -> `/api/admin/users/:id/reset-password`。

## 个人中心接口
- `POST /api/user/updateProfile` body: `{ nickname }`（当前用户）
- `POST /api/user/changePassword` body: `{ oldPassword, newPassword }`
成功返回 `{ success: true, user? }`，失败返回 `{ error }`。

## 后台接口摘要
- 角色：`normal` / `admin` / `super_admin`
- 激活码：`/api/activation/use`，`/api/activation/batch-generate`，`/api/activation/list`
- 统计：`/api/admin/stats/overview`
- 用户：`/api/admin/users` 列表，`/api/admin/users/:id/set-role`（super_admin），`/api/admin/users/:id/reset-password`（super_admin）

## 提示词
- 路径：`public/prompts/CARD_SCENARIO.txt`
- 默认 scenario：`card`（前端 `DEFAULT_SCENARIO`，后端 SCENARIO_PROMPTS 映射到同一文件）

## 说明
- 密码哈希与登录校验复用现有 `hashPassword`/`verifyPassword`。
- 静态文件下的中文 UI 文案已改为卡牌解读语境；代码中变量/函数均为英文。
- 受保护目录：`/public` 资源不可删除；`/data` 不修改；配置文件勿改，除非明确要求。***
