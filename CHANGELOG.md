# Changelog

All notable changes to the GateKeeper project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-05-15

### Added
- **ISO 安装支持**: 新增 Debian 10 (Buster) ISO 一键安装，支持 BIOS 和 UEFI 双启动模式。
- **Preseed 自动化**: 使用 preseed.cfg 实现全自动化 Debian 安装，使用 archive.debian.org 镜像源。
- **首次登录密码修改**: login.html 新增密码修改表单，支持 `must_change_password` 状态处理。
- **密码强度实时验证**: 密码修改表单实时显示密码复杂度要求（长度、大小写、数字、特殊字符）。
- **CSRF Token 支持**: gateway_antivirus.html 的 apiPost 函数自动携带 CSRF token。
- **延迟导入保护**: core/app.py 新增 `_lazy_import()` 函数，模块导入失败时不会导致系统崩溃。
- **EnvironmentFile 支持**: systemd 服务通过 EnvironmentFile 传递初始密码。

### Changed
- **目标平台**: 从 Debian 12 / Python 3.10+ 降级为 Debian 10 / Python 3.7+。
- **UserRole 枚举**: 枚举值从小写（`super_admin`）改为大写（`SUPER_ADMIN`），兼容数据库存储。
- **Web 端口**: 默认端口从 8080 改为 8443。
- **安装方式**: 新增 ISO 安装为推荐安装方式。

### Fixed
- **CSRF 拦截登录**: 对 auth 蓝图豁免 CSRF 检查，修复登录请求被拦截返回 HTTP 400 的问题。
- **CSRF 拦截密码修改**: 对 change-password 接口豁免 CSRF 检查，修复首次登录修改密码失败的问题。
- **CSRF 拦截病毒库更新**: gateway_antivirus.html 的 apiPost 函数添加 X-CSRFToken 请求头。
- **flask_limiter 导入失败**: 将 flask_limiter 改为可选依赖（try/except），未安装时跳过速率限制。
- **mitmproxy 兼容性**: 注释掉 mitmproxy 依赖（需要 Python 3.8+，Debian 10 默认 3.7）。
- **DetachedInstanceError**: auth.py 登录成功后调用 session.expunge(user) 防止会话关闭后访问属性报错。
- **密码修改循环**: settings.py api_change_password 添加 `user.must_change_password = False`。
- **安装卡在 33%**: preseed.cfg 移除 `standard` 任务，只安装 `ssh-server`，大幅减少 apt 包数量。
- **安装源不可用**: preseed.cfg 使用 archive.debian.org 替代已归档的 cdn.debian.org。
- **密码生成时序**: first-start.sh 在 systemctl start 之前生成密码并写入 EnvironmentFile。
- **ISO 体积膨胀**: 构建脚本排除 *.iso 文件，防止旧 ISO 被打包进新 ISO。
- **routing.py 语法错误**: _safe_error_message 导入位置修正。
- **gateway_av 双重 url_prefix**: Blueprint 构造函数移除重复的 url_prefix。

## [1.0.4] - 2026-05-12

### Added
- **Security Fixes**: SSE broadcast authentication, CSRF protection, input validation, and rate limiting.
- **.gitignore**: Comprehensive gitignore rules for Python, IDE, project data, and build artifacts.
- **.pre-commit-config.yaml**: Pre-commit hooks for black, flake8, isort, and common file checks.
- **Test Suite**: Added 189 test cases covering core modules, web routes, network modules, and CLI.

### Changed
- **README.md**: Updated project name to GateKeeper, fixed CLI command to `gk-cli`, added Docker deployment section, CI status badges placeholder, and environment variables documentation.
- **CONTRIBUTING.md**: Updated Python version requirement to 3.10+, fixed test file references, updated black target version to py310.
- **.dockerignore**: Added entries for scripts/, tests/, docs/, .env, .pre-commit-config.yaml, and alembic/.
- **setup.py**: Added `flasgger>=0.9.7.1` and `flask-limiter>=3.5.0` to install_requires.

### Fixed
- **Dockerfile**: Added non-root user (gkuser), LABEL metadata, and HEALTHCHECK --start-period.
- **CI/CD Pipeline**: Updated Python version matrix to [3.10, 3.11, 3.12], fixed Bandit scan path, pinned Safety to v1, renamed workflow, added pip cache step, increased coverage threshold to 60.
- **Memory Leaks**: Fixed memory leaks and thread safety issues across core modules.

## [1.0.3] - 2026-05-12

### Added
- **Docker Support**: Added application `Dockerfile` with Python 3.11-slim base image, health check, and proper dependency installation.
- **Docker Compose**: Added `docker-compose.yml` with gatekeeper service configuration and optional PostgreSQL service (commented out by default).
- **Database Backup Script**: Added `scripts/backup.sh` for automated SQLite database backups with timestamp, gzip compression, and 7-day retention policy. Supports cron scheduling.
- **JSON Structured Logging**: Added `JsonFormatter` class to `config/logging_config.py` for JSON-formatted log output. Configurable via `GK_LOG_FORMAT=json` environment variable.
- **Prometheus Metrics**: Added `core/metrics.py` with `MetricsCollector` singleton class providing counter, gauge, and histogram metrics with Prometheus text format output. Pre-defined metrics include `gatekeeper_http_requests_total`, `gatekeeper_active_sessions`, `gatekeeper_packets_captured`, `gatekeeper_alerts_total`, and `gatekeeper_blocked_requests`.
- **Docker Ignore**: Added `.dockerignore` to exclude unnecessary files from Docker build context.
- **Changelog**: Added this `CHANGELOG.md` file to track project changes.

### Changed
- **SSH Security**: Tightened SSH configuration in `scripts/first-start.sh`:
  - Changed `PermitRootLogin` from `yes` to `prohibit-password` (key-based auth only for root).
  - Added `MaxAuthTries 3` to limit authentication attempts.
  - Added `LoginGraceTime 30` to limit connection window.
  - Added comment recommending key-based authentication for regular users.

### Fixed
- **Alert Aggregation Timer**: Fixed the `_aggregation_timer` in `alerting/alert_manager.py` that was declared but never started. Added a `start()` method and `_run_aggregation_loop()` that uses `threading.Timer` to periodically process the aggregation buffer.
- **Scheduler Persistent Job Store**: Fixed `core/scheduler.py` to support `SQLAlchemyJobStore` when a database is available, falling back to `MemoryJobStore` if the database is not reachable. This prevents job loss on application restart.
