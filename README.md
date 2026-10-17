# 云端压缩包资源平台（可运行基础版）

功能：
- 邀请码注册（邀请码由管理员创建，可设置使用次数）
- 用户登录/退出
- 用户提交资源：名称、说明、封面图、ZIP/7Z/RAR 压缩包
- 管理员审核、批准或拒绝
- 只有已批准资源会出现在资源列表中
- 登录用户可下载已批准资源
- 文件存储在 data/，数据库在 data/app.db
- Docker 自动重启并持久化数据

## 重要安全说明
这是可运行的基础版本，不应在未配置 HTTPS、强密码、备份和反向代理限制的情况下直接暴露到公网。
- 上传文件扩展名和大小会校验，但不会自动扫描恶意文件。
- 不要解压用户上传的压缩包到服务器。
- 生产部署建议使用 Caddy/Nginx 配置 HTTPS，并把 `SESSION_HTTPS_ONLY=true`。
- SQLite 适合小规模起步；高并发时可迁移到 PostgreSQL/对象存储。
- 管理员密码在首次启动时从 `.env` 读取；若管理员账号已存在，改环境变量不会自动重置数据库中的密码。
- 需定期备份整个 `data/` 目录。

## 本地或 VPS 部署
1. 安装 Docker Engine 和 Docker Compose 插件。
2. 将项目上传到服务器并进入项目目录。
3. 复制环境配置：
   `cp .env.example .env`
4. 编辑 `.env`，设置长随机 `SECRET_KEY` 和强 `ADMIN_PASSWORD`。
   生成随机密钥示例：`openssl rand -hex 32`
5. 启动：
   `docker compose up -d --build`
6. 查看日志：
   `docker compose logs -f`
7. 打开 `http://服务器IP:8000`。

## 首次使用
1. 用 `.env` 中的管理员账号密码登录。
2. 进入“管理后台”创建邀请码。
3. 将邀请码发给允许加入的用户。
4. 用户注册并登录，提交压缩包和封面。
5. 管理员在审核队列批准后，资源会显示在首页并允许下载。

## 公网部署建议
- 购买或申请一台 Linux VPS，确保有足够磁盘空间。
- 配置域名 DNS 指向 VPS。
- 在服务器上用 Caddy 或 Nginx 配置 HTTPS 反向代理到 `127.0.0.1:8000`。
- 配好 HTTPS 后，在 `.env` 中设 `SESSION_HTTPS_ONLY=true` 并重启。
- 不建议直接把 8000 端口裸露到公网；生产环境可将 compose 的 ports 改为 `127.0.0.1:8000:8000`，只让反向代理访问。
- 限制反向代理请求体大小时，要确保其与 `MAX_UPLOAD_MB` 一致。

## 备份与更新
备份：`tar -czf resource-backup-$(date +%F).tar.gz data .env`
更新代码后：`docker compose up -d --build`
停止：`docker compose down`
