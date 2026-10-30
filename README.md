# CLOUD FILE CENTER · 星渊资源库

基于 **FastAPI + Jinja2 + PostgreSQL + S3 兼容对象存储** 的资源分享平台。前端采用深空星云、金蓝金属渐变与毛玻璃视觉体系，兼容手机和桌面浏览器。

> 当前恢复与开发分支：`recovery/restore-features-20261030`。本分支用于找回历史功能和继续开发；未经测试与人工确认，不得部署到生产服务器。

## 当前仓库功能基线

- 邀请码注册、登录与退出；邀请码支持批量创建、使用次数与启停管理。
- 用户提交 ZIP、7Z、RAR、APK 资源，附带名称、说明和封面，进入管理员审核队列。
- 仅已批准资源公开展示和下载；资源详情、个人投稿管理。
- 首页资源搜索、资源类型筛选、最新/热门/名称排序、社区统计与下载排行榜。
- 管理员查看待审核资源、查看 ZIP/APK 条目清单及安全文本预览。
- 上传文件格式与大小校验、SHA-256 摘要、ZIP 路径穿越/符号链接检查。
- ClamAV INSTREAM 扫描集成；扫描服务未配置或不可用时，结果为 unavailable，不能当作 clean 放行。
- 对象存储容量统计与平台配额、对象存储上传/下载/删除、可选 Zstandard 无损压缩。
- 管理员 IP 封禁/解封、安全审计日志、问题反馈和应用错误日志。
- CSRF 防护、登录失败限速、请求频率限制、可信代理 IP 解析。
- GitHub Actions：Python 编译、Jinja2 模板解析、pytest、安全检查和 Compose 配置检查。

### 已知限制

- 管理员压缩包内容浏览当前实现 ZIP/APK（APK 是 ZIP 容器）；7Z/RAR 内容浏览尚未接入。
- 文本预览仅允许安全路径下的常见文本文件，最大 64 KiB；不会执行或渲染文件内容。
- ClamAV 配置为空或扫描不可用时，不应批准需要扫描的资源。当前恢复分支没有替用户配置扫描服务器。
- 账号级封禁、用户密码重置等未实现功能，不应在 UI 或文档中宣称已具备。

## 架构与运行依赖

应用容器需要连接两个外部服务：

1. **PostgreSQL**：由 `DATABASE_URL` 指定。
2. **S3 兼容对象存储**：由 `AWS_ENDPOINT_URL_S3`、`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_REGION` 和 `S3_BUCKET` 指定。可使用 SeaweedFS S3 Gateway。

`docker-compose.yml` 只定义应用容器，不会自动创建 PostgreSQL 或 SeaweedFS。请先确认外部服务的网络地址、Bucket 和访问凭据，再配置环境变量。不要把数据库密码、对象存储密钥、SECRET_KEY 或管理员密码提交到 Git。

## 环境变量

复制模板后按实际部署环境填写：

```bash
cp .env.example .env
```

必需配置：

- `SECRET_KEY`：长随机会话密钥。
- `ADMIN_PASSWORD`：强管理员密码。
- `DATABASE_URL`：PostgreSQL 连接字符串。
- `AWS_ENDPOINT_URL_S3`：S3 兼容 API 地址。
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`：对象存储凭据。

常用可选配置：

- `MAX_UPLOAD_MB`：单个上传文件上限，默认 2048。
- `S3_BUCKET`：Bucket 名称，默认 `archive-files`。
- `SESSION_HTTPS_ONLY`：HTTPS 部署后设为 `true`。
- `TRUSTED_PROXY_IPS`：仅填写可信反向代理的 IP。
- `CLAMAV_HOST` / `CLAMAV_PORT`：ClamAV clamd 服务地址；未配置时扫描不可用，不能视为扫描通过。

生成随机密钥示例：

```bash
openssl rand -hex 32
```

## 本地开发与验证

需要 Python 3.12、Docker Compose，以及可访问的 PostgreSQL 和 S3 兼容存储。

```bash
python -m pip install -r requirements.txt
python -m pip install pytest
python -m compileall -q app tests
pytest -q
docker compose config -q
```

Compose 配置检查需要先提供占位环境变量或真实的本地测试配置；不要把生产密钥用于 CI。

## 启动应用容器

确认 PostgreSQL、对象存储、Bucket 和网络访问均已就绪，填写 `.env` 后：

```bash
docker compose up -d --build
docker compose logs --tail=100 resource-platform
```

默认仅绑定 `127.0.0.1:8000`，应由 Nginx 等反向代理通过 HTTPS 对外提供服务。反向代理的请求体上限必须大于等于应用上传上限，并考虑 multipart 开销。

## 安全与恢复纪律

- 开发只在独立分支进行；`main` 和生产服务器保持不动，除非用户明确批准。
- 每次修改先检查 Git 差异；禁止未经确认的自动注入、覆盖或生产部署。
- 不要将真实 `.env`、密钥、数据库导出、用户上传文件或对象存储凭据提交到仓库。
- 部署前必须备份数据库和对象存储元数据/对象，并确认恢复步骤。
- 数据库结构由应用启动时的幂等初始化逻辑维护；任何迁移都必须先在测试数据库验证。
- 不要通过删除数据目录、重建 Bucket 或清空数据库来处理代码部署问题。
- 发生 5xx 时先保留日志、容器状态和当前镜像，再诊断；不要先清理现场。

## 版本与发布

当前分支是恢复开发基线，不是生产发布。合并到 `main` 前必须满足：

1. GitHub Actions 全部通过。
2. 所有 Jinja2 模板可解析。
3. 现有测试通过，并补齐新增功能回归测试。
4. 在隔离环境验证登录、邀请码、上传、审核、扫描、下载、删除和对象存储读写。
5. 对照目标 VPS 的 PostgreSQL、SeaweedFS、Nginx 与环境变量逐项确认。
6. 用户明确批准后才创建正式 Release 和部署计划。
