# 云端压缩包资源平台

这是基于 FastAPI、PostgreSQL 和 S3 兼容对象存储的多人资源平台。功能包括邀请码注册、用户登录、资源提交、管理员审核、已审核资源浏览与下载。

## 当前架构（请先读）

当前 `app/main.py` **不是旧版 SQLite + 本地 `data/` 文件存储架构**。它启动时要求 `SECRET_KEY` 和 `DATABASE_URL`，数据库使用 PostgreSQL；压缩包和封面保存在 S3 兼容对象存储中。仅复制旧版的 `.env.example` 并执行 `docker compose up` 不足以启动当前版本。

- PostgreSQL：保存用户、邀请码、资源元数据和审核状态。
- S3 兼容对象存储：保存资源文件和封面。需要单独提供 endpoint、bucket、region 和访问凭据。
- 应用容器：运行 FastAPI/Uvicorn。
- `/health`：检查数据库连接，并报告对象存储配置是否存在；**它不会真正执行对象存储读写**，因此 `storage=configured` 不等于上传/下载链路已通过验证。

## 使用 Docker Compose 部署

需要安装 Docker Engine 和 Docker Compose 插件，并先准备一个 PostgreSQL 可用的环境以及一个 S3 兼容对象存储 bucket。Compose 会启动应用和 PostgreSQL；对象存储需要你另行选择和配置。

1. 复制环境模板：

   ```sh
   cp .env.example .env
   ```

2. 编辑 `.env`，至少设置：
   - 长随机的 `SECRET_KEY`
   - 唯一且强的 `ADMIN_PASSWORD`
   - `POSTGRES_PASSWORD`（使用 URL 安全字符，例如字母和数字；并将同一值填入 `DATABASE_URL`）
   - 有效的 `AWS_ENDPOINT_URL_S3`、`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_REGION` 和 `S3_BUCKET`
   - 本地直接通过 HTTP 测试时保持 `SESSION_HTTPS_ONLY=false`；只有 HTTPS 反向代理已经正确工作后才设为 `true`。不要在没有 HTTPS 的情况下启用 Secure 会话 Cookie，否则浏览器不会在普通 HTTP 下发送登录会话。

   `DATABASE_URL` 中的用户名、密码、数据库名必须与 PostgreSQL 服务的 `POSTGRES_USER`、`POSTGRES_PASSWORD`、`POSTGRES_DB` 一致。若密码含有 URL 特殊字符，必须先对连接串中的密码部分做 URL 编码。

3. 生成随机会话密钥的示例：

   ```sh
   openssl rand -hex 32
   ```

4. 启动：

   ```sh
   docker compose up -d --build
   docker compose ps
   docker compose logs -f resource-platform
   ```

5. 访问 `http://服务器地址:8000`。正式公网使用前，应配置 HTTPS 反向代理、防火墙规则和可靠的备份；不要将数据库端口直接暴露到公网。

## 首次使用

1. 用 `.env` 中的管理员账号密码登录。
2. 在管理后台创建邀请码。
3. 用户使用邀请码注册并登录。
4. 用户提交资源，管理员审核通过后资源才会公开显示并允许下载。

## 上传限制与存储费用

- `MAX_UPLOAD_MB` 是**单个压缩包/APK 的上传大小上限**，不是平台总存储配额。
- 当前代码没有实现平台级 5 GB 总容量限制。若目标是所有用户合计不超过 5 GB，需要单独实现并测试配额逻辑；不能仅靠单文件限制保证。
- 对象存储费用、免费额度、请求费用、流量费用、生命周期策略及恢复能力由你选择的存储提供商决定。**本项目不能保证总费用为 $0/月**；设置环境变量也不会自动获得免费存储。
- 当前代码主要检查文件扩展名和部分文件签名，没有完整的恶意软件扫描。不要解压用户上传的压缩包到应用服务器。

## 备份与恢复

数据库和对象存储必须分别备份；仅备份代码或数据库不包含上传文件。

- PostgreSQL：使用 `pg_dump` 定期导出，并把备份存放在独立且受保护的位置。
- 对象存储：确认提供商是否支持版本控制/生命周期/独立备份，并定期验证对象可恢复性。
- 将 `.env` 作为敏感凭据妥善保管，**不要提交到 GitHub 或放入公开备份**。
- 在没有完成恢复演练前，不要把备份方案视为已验证。

## 更新与停止

```sh
docker compose up -d --build
docker compose logs -f resource-platform
docker compose down
``

`docker compose down` 不会删除命名 PostgreSQL 卷。不要使用 `docker compose down -v`，除非你明确希望删除数据库卷并已确认备份。
