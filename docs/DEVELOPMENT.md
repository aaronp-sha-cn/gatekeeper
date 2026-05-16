# GateKeeper 开发手册

> AI 安全网络防御系统 v1.1.0 | 最后更新：2026-05-14

---

## 目录

- [一、环境搭建](#一环境搭建)
  - [1.1 系统要求](#11-系统要求)
  - [1.2 克隆与安装](#12-克隆与安装)
  - [1.3 环境变量配置](#13-环境变量配置)
  - [1.4 启动方式](#14-启动方式)
  - [1.5 Docker 部署](#15-docker-部署)
  - [1.6 ISO 部署](#16-iso-部署)
- [二、项目架构](#二项目架构)
  - [2.1 目录结构](#21-目录结构)
  - [2.2 核心架构图 (ASCII)](#22-核心架构图-ascii)
  - [2.3 初始化流程](#23-初始化流程)
  - [2.4 单例模式](#24-单例模式)
  - [2.5 延迟导入机制](#25-延迟导入机制)
- [三、配置系统](#三配置系统)
  - [3.1 配置类一览](#31-配置类一览)
  - [3.2 环境变量读取](#32-环境变量读取)
  - [3.3 配置持久化](#33-配置持久化)
  - [3.4 数据库配置](#34-数据库配置)
- [四、数据模型](#四数据模型)
  - [4.1 枚举类型](#41-枚举类型)
  - [4.2 模型关系图 (ASCII)](#42-模型关系图-ascii)
  - [4.3 模型详细说明](#43-模型详细说明)
  - [4.4 数据库会话使用模式](#44-数据库会话使用模式)
- [五、Web 应用开发](#五web-应用开发)
  - [5.1 应用工厂](#51-应用工厂)
  - [5.2 蓝图列表](#52-蓝图列表)
  - [5.3 API 路由规范](#53-api-路由规范)
  - [5.4 认证与权限](#54-认证与权限)
  - [5.5 CSRF 保护](#55-csrf-保护)
  - [5.6 速率限制](#56-速率限制)
  - [5.7 错误处理](#57-错误处理)
  - [5.8 实时推送 (SSE)](#58-实时推送-sse)
  - [5.9 添加新蓝图指南](#59-添加新蓝图指南)
- [六、安全模块开发](#六安全模块开发)
  - [6.1 模块概览](#61-模块概览)
  - [6.2 模块开发规范](#62-模块开发规范)
  - [6.3 IDS 引擎开发](#63-ids-引擎开发)
  - [6.4 防火墙规则开发](#64-防火墙规则开发)
  - [6.5 VPN 服务开发](#65-vpn-服务开发)
- [七、AI 引擎开发](#七ai-引擎开发)
  - [7.1 模块概览](#71-模块概览)
  - [7.2 模型管理](#72-模型管理)
  - [7.3 LLM 集成](#73-llm-集成)
  - [7.4 异常检测](#74-异常检测)
  - [7.5 添加新 AI 模块指南](#75-添加新-ai-模块指南)
- [八、网络模块开发](#八网络模块开发)
  - [8.1 模块概览](#81-模块概览)
  - [8.2 数据包捕获](#82-数据包捕获)
  - [8.3 网关管理](#83-网关管理)
  - [8.4 动态路由](#84-动态路由)
- [九、CLI 开发](#九cli-开发)
  - [9.1 Junos 风格 CLI](#91-junos-风格-cli)
  - [9.2 命令注册](#92-命令注册)
  - [9.3 添加新命令指南](#93-添加新命令指南)
- [十、前端开发](#十前端开发)
  - [10.1 模板结构](#101-模板结构)
  - [10.2 JavaScript 规范](#102-javascript-规范)
  - [10.3 添加新页面指南](#103-添加新页面指南)
- [十一、测试](#十一测试)
  - [11.1 测试框架](#111-测试框架)
  - [11.2 测试文件](#112-测试文件)
  - [11.3 运行测试](#113-运行测试)
  - [11.4 编写测试指南](#114-编写测试指南)
- [十二、编码规范](#十二编码规范)
  - [12.1 Python 规范](#121-python-规范)
  - [12.2 命名规范](#122-命名规范)
  - [12.3 文档规范](#123-文档规范)
  - [12.4 Git 规范](#124-git-规范)
  - [12.5 安全编码规范](#125-安全编码规范)
- [十三、调试与排障](#十三调试与排障)
  - [13.1 日志系统](#131-日志系统)
  - [13.2 常见问题](#132-常见问题)
  - [13.3 调试模式](#133-调试模式)
- [十四、部署指南](#十四部署指南)
  - [14.1 ISO 部署](#141-iso-部署)
  - [14.2 systemd 服务](#142-systemd-服务)
  - [14.3 SSL 证书](#143-ssl-证书)
  - [14.4 备份与恢复](#144-备份与恢复)
  - [14.5 安全加固](#145-安全加固)
- [附录](#附录)
  - [A. 依赖清单](#a-依赖清单)
  - [B. 默认端口](#b-默认端口)
  - [C. 默认账户](#c-默认账户)
  - [D. API 端点速查表](#d-api-端点速查表)
  - [E. 常用命令速查](#e-常用命令速查)

---

## 一、环境搭建

### 1.1 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Debian 10 (Buster) / Ubuntu 20.04+ |
| Python | >= 3.7 (推荐 3.10+) |
| 系统依赖 | `libpcap-dev`, `libssl-dev`, `libffi-dev`, `build-essential` |
| 可选依赖 | `libcap2-bin` (scapy raw socket), `ClamAV` (antivirus) |
| 磁盘空间 | >= 2GB (含模型和日志) |
| 内存 | >= 2GB (推荐 4GB+) |

安装系统依赖（Debian/Ubuntu）:

```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev libssl-dev libffi-dev build-essential
# 可选
sudo apt-get install -y libcap2-bin clamav
```

### 1.2 克隆与安装

```bash
# 克隆项目
git clone https://github.com/gatekeeper-security/gatekeeper.git gatekeeper
cd gatekeeper

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 验证安装
python3 -c "from config.settings import settings; print('GateKeeper v{}'.format(settings.version))"
```

开发环境额外安装:

```bash
pip install pytest pytest-cov black flake8 mypy
```

### 1.3 环境变量配置

所有环境变量使用 `GK_` 前缀。以下是完整的环境变量列表:

#### 数据库配置 (GK_DB_*)

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `GK_DB_DRIVER` | `sqlite` | 数据库驱动: `sqlite` / `postgresql` |
| `GK_DB_URL` | (自动生成) | 数据库连接URL (优先级高于单独配置) |
| `GK_DB_SQLITE_PATH` | `data/gatekeeper.db` | SQLite 数据库文件路径 |
| `GK_DB_PG_HOST` | `localhost` | PostgreSQL 主机 |
| `GK_DB_PG_PORT` | `5432` | PostgreSQL 端口 |
| `GK_DB_PG_USER` | `gatekeeper` | PostgreSQL 用户名 |
| `GK_DB_PG_PASSWORD` | `gatekeeper_secret` | PostgreSQL 密码 |
| `GK_DB_PG_DATABASE` | `gatekeeper` | PostgreSQL 数据库名 |
| `GK_DB_POOL_SIZE` | `10` | 连接池大小 |
| `GK_DB_MAX_OVERFLOW` | `20` | 连接池最大溢出数 |
| `GK_DB_POOL_TIMEOUT` | `30` | 连接池超时 (秒) |
| `GK_DB_POOL_RECYCLE` | `3600` | 连接回收时间 (秒) |
| `GK_DB_ECHO` | `false` | 是否输出SQL日志 |

#### Web 配置 (GK_WEB_*)

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `GK_WEB_HOST` | `0.0.0.0` | Web 监听地址 |
| `GK_WEB_PORT` | `8443` | Web 监听端口 |
| `GK_WEB_SSL_ENABLED` | `true` | 是否启用 HTTPS |
| `GK_WEB_SECRET_KEY` | (空) | 会话加密密钥 (生产环境必须设置) |
| `GK_WEB_SSL_CERT` | `data/certs/server.crt` | SSL 证书路径 |
| `GK_WEB_SSL_KEY` | `data/certs/server.key` | SSL 密钥路径 |
| `GK_WEB_SESSION_TIMEOUT` | `60` | 会话超时 (分钟) |
| `GK_WEB_MAX_LOGIN_ATTEMPTS` | `5` | 最大登录尝试次数 |
| `GK_WEB_LOGIN_LOCKOUT` | `30` | 登录锁定时间 (分钟) |
| `GK_WEB_RATE_LIMIT` | `100` | API 速率限制 (请求/分钟) |
| `GK_WEB_DEBUG` | `false` | 调试模式 |

#### 管理员初始密码

| 环境变量 | 说明 |
|----------|------|
| `GK_ADMIN_SP_PASSWORD` | 超级管理员 (admin-sp) 初始密码 |
| `GK_ADMIN_PASSWORD` | 管理员 (admin) 初始密码 |

> 未设置时自动生成16位随机密码，写入 `/opt/gatekeeper/.initial_credentials` 文件。

#### AI 模型配置 (GK_AI_*)

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `GK_AI_MODEL_PATH` | `models/` | 模型存储路径 |
| `GK_AI_ANOMALY_THRESHOLD` | `0.85` | 异常检测阈值 |
| `GK_AI_ANALYSIS_WINDOW` | `60` | 流量分析窗口 (秒) |
| `GK_AI_FEATURE_DIMENSIONS` | `32` | 特征提取维度 |
| `GK_AI_BATCH_SIZE` | `256` | 训练批量大小 |
| `GK_AI_TRAINING_EPOCHS` | `100` | 训练轮次 |
| `GK_AI_LEARNING_RATE` | `0.001` | 学习率 |
| `GK_AI_ONLINE_LEARNING` | `true` | 是否启用在线学习 |
| `GK_AI_ONLINE_UPDATE_INTERVAL` | `3600` | 在线学习更新间隔 (秒) |
| `GK_AI_IDS_CONFIDENCE` | `0.7` | IDS 规则置信度阈值 |
| `GK_AI_VULN_CONCURRENCY` | `10` | 漏洞扫描并发数 |

#### 告警配置 (GK_ALERT_*)

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `GK_ALERT_DEFAULT_LEVEL` | `medium` | 默认告警级别 |
| `GK_ALERT_EMAIL_ENABLED` | `false` | 是否启用邮件告警 |
| `GK_ALERT_SMTP_HOST` | `smtp.gmail.com` | SMTP 服务器 |
| `GK_ALERT_SMTP_PORT` | `587` | SMTP 端口 |
| `GK_ALERT_SMTP_USER` | (空) | SMTP 用户名 |
| `GK_ALERT_SMTP_PASSWORD` | (空) | SMTP 密码 |
| `GK_ALERT_SMTP_TLS` | `true` | 是否启用 TLS |
| `GK_ALERT_EMAIL_RECIPIENTS` | `[]` | 邮件收件人列表 (JSON数组) |
| `GK_ALERT_EMAIL_SENDER` | `gatekeeper@localhost` | 发件人地址 |
| `GK_ALERT_EMAIL_PREFIX` | `[GateKeeper]` | 邮件主题前缀 |
| `GK_ALERT_WEBHOOK_ENABLED` | `false` | 是否启用 Webhook 告警 |
| `GK_ALERT_WEBHOOK_URLS` | `[]` | Webhook URL 列表 (JSON数组) |
| `GK_ALERT_WEBHOOK_TIMEOUT` | `10` | Webhook 超时 (秒) |
| `GK_ALERT_COOLDOWN` | `300` | 告警冷却时间 (秒) |
| `GK_ALERT_AGGREGATION` | `60` | 告警聚合窗口 (秒) |
| `GK_ALERT_MAX_PER_MINUTE` | `10` | 最大告警频率 (每分钟) |

#### 日志配置 (GK_LOG_*)

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `GK_LOG_LEVEL` | `INFO` | 日志级别: `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |
| `GK_LOG_FILE` | `logs/gatekeeper.log` | 日志文件路径 |
| `GK_LOG_MAX_SIZE` | `100` | 最大日志文件大小 (MB) |
| `GK_LOG_BACKUP_COUNT` | `10` | 保留日志文件数量 |
| `GK_LOG_CONSOLE` | `true` | 是否输出到控制台 |
| `GK_LOG_FILE_OUTPUT` | `true` | 是否输出到文件 |
| `GK_LOG_SECURITY_AUDIT` | `true` | 是否启用安全审计日志 |
| `GK_LOG_SECURITY_PATH` | `logs/security_audit.log` | 安全审计日志路径 |
| `GK_LOG_FORMAT` | (标准) | 日志格式: `json` 启用 JSON 结构化日志 |

#### 调度器配置 (GK_SCHED_*)

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `GK_SCHED_EXECUTOR` | `background` | 调度器类型: `background` / `gevent` |
| `GK_SCHED_MAX_WORKERS` | `10` | 最大工作线程数 |
| `GK_SCHED_TRAFFIC_INTERVAL` | `30` | 流量分析间隔 (秒) |
| `GK_SCHED_ANOMALY_INTERVAL` | `60` | 异常检测间隔 (秒) |
| `GK_SCHED_VULN_INTERVAL` | `3600` | 漏洞扫描间隔 (秒) |
| `GK_SCHED_THREAT_INTERVAL` | `1800` | 威胁情报更新间隔 (秒) |
| `GK_SCHED_MODEL_INTERVAL` | `3600` | 模型在线学习间隔 (秒) |
| `GK_SCHED_REPORT_INTERVAL` | `86400` | 报表生成间隔 (秒) |
| `GK_SCHED_CLEANUP_INTERVAL` | `86400` | 数据清理间隔 (秒) |
| `GK_SCHED_DATA_RETENTION` | `30` | 数据保留天数 |

#### 网络配置 (GK_NET_*)

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `GK_NET_INTERFACE` | `eth0` | 监听网络接口 |
| `GK_NET_CAPTURE_MODE` | `live` | 抓包模式: `live` / `pcap_file` |
| `GK_NET_PCAP_FILE` | (空) | PCAP 文件路径 (离线分析) |
| `GK_NET_BPF_FILTER` | (空) | BPF 过滤规则 |
| `GK_NET_BUFFER_SIZE` | `256` | 抓包缓冲区大小 (MB) |
| `GK_NET_MAX_PACKET_SIZE` | `65535` | 最大包大小 (字节) |
| `GK_NET_PROMISCUOUS` | `true` | 是否启用混杂模式 |
| `GK_NET_MONITORED_PORTS` | `[]` | 监控端口列表 (JSON数组) |
| `GK_NET_EXCLUDED_IPS` | `[]` | 排除IP列表 (JSON数组) |
| `GK_NET_SAMPLING_RATE` | `1.0` | 流量采样率 (0.0-1.0) |
| `GK_NET_CAPTURE_TIMEOUT` | `300` | 抓包超时 (秒) |
| `GK_NET_IPV6_ENABLED` | `false` | 是否启用 IPv6 |
| `GK_NET_IPV6_INTERFACE` | (空) | IPv6 监听接口 |

#### 其他配置

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `GK_INSTANCE_NAME` | `default` | 实例名称 (多实例部署时区分) |

### 1.4 启动方式

```bash
# 开发模式 - 启动 Web 管理面板
python3 -m core.app --web

# 启动 Web 管理面板 + 数据包捕获
python3 -m core.app --web --capture

# 仅初始化数据库 (不启动服务)
python3 -m core.app --init-only

# 不启动 Web 面板 (后台模式)
python3 -m core.app --no-web

# 查看版本信息
python3 -m core.app --version

# 通过 CLI 入口 (安装后)
gk-cli          # 通用 CLI
gk-junos        # Junos 风格 CLI
gk-cisco        # Cisco 风格 CLI
gatekeeper      # 主服务
```

命令行参数说明:

| 参数 | 说明 |
|------|------|
| `--web` | 启动 Web 管理面板 (默认行为) |
| `--no-web` | 不启动 Web 管理面板 |
| `--capture` | 启动数据包捕获 |
| `--init-only` | 仅初始化数据库，不启动服务 |
| `--version` | 显示版本信息 |

### 1.5 Docker 部署

项目提供 `Dockerfile` 和 `docker-compose.yml` 用于容器化部署。

**Dockerfile 概览:**

- 基础镜像: `python:3.11-slim`
- 系统依赖: `libpcap-dev`, `libcap2-bin`, `iptables`, `libnet1`
- 工作目录: `/opt/gatekeeper`
- 暴露端口: `8443`, `8080`
- 健康检查: HTTP GET `/health`

**docker-compose.yml 概览:**

```yaml
version: "3.8"
services:
  gatekeeper:
    build: .
    container_name: gatekeeper
    restart: unless-stopped
    ports:
      - "8443:8443"
      - "8080:8080"
    volumes:
      - gatekeeper-data:/opt/gatekeeper/data
      - gatekeeper-logs:/opt/gatekeeper/logs
      - gatekeeper-models:/opt/gatekeeper/models
    environment:
      - GK_WEB_PORT=8080
      - GK_WEB_SSL_ENABLED=false
      - GK_WEB_SECRET_KEY=${GK_WEB_SECRET_KEY:-change-me-in-production}
      - GK_DB_DRIVER=sqlite
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]
```

使用 Docker Compose 启动:

```bash
# 构建并启动
docker-compose up -d

# 查看日志
docker-compose logs -f gatekeeper

# 停止
docker-compose down
```

> 注: docker-compose.yml 中已注释 PostgreSQL 服务配置，取消注释即可切换到 PostgreSQL。

### 1.6 ISO 部署

项目支持通过 `iso_build/` 目录构建可启动的 ISO 镜像，用于裸机部署。

**关键文件:**

| 文件 | 说明 |
|------|------|
| `iso_build/build_iso_debian10.sh` | 基于 Debian 10 的 ISO 构建脚本 |
| `iso_build/build_iso_pycdlib.py` | 使用 pycdlib 的 ISO 构建脚本 |
| `iso_build/preseed.cfg` | Debian 自动安装预配置文件 |
| `iso_build/late-command.sh` | 安装后执行脚本 |
| `iso_build/postinstall.sh` | 安装后配置脚本 |
| `iso_build/Dockerfile` | ISO 构建环境 Dockerfile |

**构建流程:**

```bash
cd iso_build
# 使用 Debian 10 构建
sudo bash build_iso_debian10.sh
# 或使用 pycdlib 构建
python3 build_iso_pycdlib.py
```

ISO 安装后首次启动时，`scripts/first-start.sh` 会自动完成:
1. 设置目录权限
2. 配置 SSH 访问
3. 配置 Junos 风格 CLI 为默认 shell
4. 创建 Python 虚拟环境
5. 安装 Python 依赖
6. 初始化数据库
7. 生成 SSL 证书
8. 配置 systemd 服务
9. 配置 iptables 防火墙
10. 配置 fail2ban
11. 清理安装标记

---

## 二、项目架构

### 2.1 目录结构

```
gatekeeper/
├── ai_engine/              # AI 引擎模块 (14个文件)
│   ├── __init__.py
│   ├── adaptive_defense.py # 自适应防御
│   ├── ai_config.py        # AI 配置管理
│   ├── anomaly_detector.py # 异常检测器
│   ├── attack_chain.py     # 攻击链分析
│   ├── behavior_analyzer.py # 行为分析 (UEBA)
│   ├── ids_optimizer.py    # IDS 规则优化器
│   ├── intelligent_response.py # 智能响应
│   ├── llm_provider.py     # LLM 多提供商接口
│   ├── model_manager.py    # 模型管理器
│   ├── risk_assessment.py  # 风险评估
│   ├── threat_intelligence.py # 威胁情报管理
│   ├── traffic_analyzer.py # 流量分析器
│   ├── traffic_predictor.py # 流量预测
│   └── vuln_scanner.py     # 漏洞扫描器
│
├── alerting/               # 告警系统
│   ├── __init__.py
│   ├── alert_manager.py    # 告警管理器
│   ├── email_alert.py      # 邮件告警
│   └── webhook_alert.py    # Webhook 告警
│
├── cli/                    # 命令行界面
│   ├── __init__.py
│   ├── cisco_cli.py        # Cisco 风格 CLI
│   ├── commands.py         # 命令处理器
│   ├── completer.py        # 命令补全
│   ├── junos_cli.py        # Junos 风格 CLI
│   ├── main.py             # CLI 入口
│   └── network_commands.py # 网络相关命令
│
├── config/                 # 配置管理
│   ├── database.py         # 数据库引擎与会话配置
│   ├── logging_config.py   # 日志系统配置
│   └── settings.py         # 全局配置 (7个配置类)
│
├── core/                   # 核心应用
│   ├── __init__.py
│   ├── app.py              # 主应用入口 (GateKeeper 单例)
│   ├── audit.py            # 审计日志
│   ├── database.py         # 数据库管理器 (DatabaseManager 单例)
│   ├── metrics.py          # 系统指标
│   ├── models.py           # SQLAlchemy ORM 数据模型
│   └── scheduler.py        # 任务调度器 (APScheduler)
│
├── docs/                   # 文档
│   ├── ARCHITECTURE.md     # 架构文档
│   └── DEVELOPMENT.md      # 开发手册 (本文件)
│
├── iso_build/              # ISO 构建
│   ├── build/              # 构建产物
│   ├── build_iso_debian10.sh
│   ├── build_iso_pycdlib.py
│   ├── preseed.cfg
│   ├── late-command.sh
│   ├── postinstall.sh
│   └── Dockerfile
│
├── logs/                   # 日志文件目录
│   ├── gatekeeper.log      # 主日志
│   ├── security_audit.log  # 安全审计日志
│   └── aegis_guard.log     # 安全防护日志
│
├── network/                # 网络模块 (13个文件)
│   ├── __init__.py
│   ├── bridge.py           # 网桥管理
│   ├── dhcp.py             # DHCP 服务
│   ├── dns_filter.py       # DNS 过滤
│   ├── dual_wan.py         # 双 WAN 负载均衡
│   ├── dynamic_routing.py  # 动态路由 (OSPF/BGP/FRR)
│   ├── firewall.py         # 防火墙管理 (iptables)
│   ├── gateway.py          # 网关管理 (NAT/DHCP/WAN/VLAN)
│   ├── network_config.py   # 网络配置管理
│   ├── packet_capture.py   # 数据包捕获 (scapy)
│   ├── port_scanner.py     # 端口扫描
│   ├── protocol_parser.py  # 协议解析
│   └── speedtest.py        # 网络测速
│
├── reports/                # 报告生成
│   ├── __init__.py
│   ├── pdf_export.py       # PDF 导出
│   └── report_generator.py # 报告生成器
│
├── scripts/                # 运维脚本
│   ├── backup.sh           # 备份脚本
│   ├── cert-manager.sh     # SSL 证书管理
│   ├── first-start.sh      # 首次启动配置
│   ├── install.sh          # 安装脚本
│   ├── run-service.sh      # 服务运行脚本
│   ├── start.sh            # 启动脚本
│   ├── stop.sh             # 停止脚本
│   └── ...
│
├── security/               # 安全模块 (31个文件)
│   ├── __init__.py
│   ├── app_detector.py     # 应用层检测
│   ├── arp_protection.py   # ARP 防护
│   ├── asset_discovery.py  # 资产发现
│   ├── auth_ldap.py        # LDAP/AD 认证
│   ├── bandwidth_manager.py # 带宽管理
│   ├── compliance_checker.py # 合规检查
│   ├── content_security.py # 内容安全
│   ├── ddos_protector.py   # DDoS 防护
│   ├── dhcp_monitor.py     # DHCP 监控
│   ├── dns_filter.py       # DNS 过滤引擎
│   ├── firewall.py         # 安全防火墙策略
│   ├── gateway_antivirus.py # 网关级防病毒
│   ├── ha_manager.py       # 高可用管理
│   ├── honeypot.py         # 蜜罐系统
│   ├── ids_engine.py       # 入侵检测引擎 (IDS/IPS)
│   ├── mac_manager.py      # MAC 地址管理
│   ├── network_isolation.py # 网络隔离
│   ├── network_scanner.py  # 网络扫描
│   ├── ntconfig_checker.py # Windows NT 配置检查
│   ├── protocol_scanners.py # 协议扫描器
│   ├── qos_manager.py      # QoS 服务质量管理
│   ├── rule_updater.py     # 规则更新器
│   ├── sandbox_analyzer.py # 沙箱分析
│   ├── siem_engine.py      # SIEM 引擎
│   ├── ssl_checker.py      # SSL 证书检查
│   ├── ssl_inspector.py    # SSL/TLS 检查
│   ├── two_factor.py       # 双因素认证 (2FA)
│   ├── vpn_service.py      # VPN 服务管理
│   ├── vuln_scanner.py     # 漏洞扫描
│   ├── waf_engine.py       # Web 应用防火墙
│   └── zero_trust.py       # 零信任架构
│
├── tests/                  # 测试套件
│   ├── __init__.py
│   ├── conftest.py         # 测试配置和公共 fixtures
│   ├── test_ai_engine.py   # AI 引擎测试
│   ├── test_alerting.py    # 告警系统测试
│   ├── test_cli.py         # CLI 测试
│   ├── test_network.py     # 网络模块测试
│   ├── test_network_modules.py # 网络模块详细测试
│   ├── test_security_modules.py # 安全模块测试
│   └── test_web_routes.py  # Web 路由测试
│
├── utils/                  # 工具函数
│   ├── __init__.py
│   ├── crypto.py           # 加密工具 (密码哈希/数据加解密)
│   ├── helpers.py          # 通用辅助函数
│   ├── ip_geo.py           # IP 地理位置查询
│   └── logger.py           # 日志工具
│
├── web/                    # Web 应用
│   ├── __init__.py
│   ├── app.py              # Flask 应用工厂
│   ├── routes/             # 路由蓝图 (34个文件)
│   │   ├── __init__.py
│   │   ├── alerts.py       # 告警管理
│   │   ├── app_control.py  # 应用控制
│   │   ├── assets.py       # 资产管理
│   │   ├── audit.py        # 审计日志
│   │   ├── auth.py         # 认证 (登录/登出/2FA)
│   │   ├── auth_ldap.py    # LDAP 认证
│   │   ├── compliance.py   # 合规管理
│   │   ├── content_security.py # 内容安全
│   │   ├── dashboard.py    # 仪表盘
│   │   ├── ddos.py         # DDoS 防护
│   │   ├── dns_filter.py   # DNS 过滤
│   │   ├── dual_wan.py     # 双 WAN
│   │   ├── gateway.py      # 网关管理
│   │   ├── gateway_av.py   # 网关防病毒
│   │   ├── ha.py           # 高可用
│   │   ├── health.py       # 健康检查
│   │   ├── honeypot.py     # 蜜罐
│   │   ├── ids.py          # IDS 管理
│   │   ├── isolation.py    # 网络隔离
│   │   ├── network.py      # 网络管理
│   │   ├── ntconfig.py     # NT 配置检查
│   │   ├── qos.py          # QoS 管理
│   │   ├── reports.py      # 报告管理
│   │   ├── routing.py      # 路由管理
│   │   ├── rule_update.py  # 规则更新
│   │   ├── sandbox.py      # 沙箱分析
│   │   ├── settings.py     # 系统设置
│   │   ├── siem.py         # SIEM 管理
│   │   ├── ssl_inspector.py # SSL 检查
│   │   ├── vpn.py          # VPN 管理
│   │   ├── vuln_scan.py    # 漏洞扫描
│   │   ├── waf.py          # WAF 管理
│   │   ├── websocket.py    # WebSocket/SSE
│   │   └── zero_trust.py   # 零信任
│   ├── templates/          # Jinja2 模板 (33个文件)
│   │   ├── base.html       # 基础布局模板
│   │   ├── login.html      # 登录页面
│   │   ├── dashboard.html  # 仪表盘
│   │   └── ...             # 各功能模块页面
│   └── static/             # 静态资源 (CSS/JS/图片)
│
├── config.py               # (deprecated, 使用 config/)
├── requirements.txt        # Python 依赖清单
├── setup.py                # 包安装配置
├── Dockerfile              # Docker 构建文件
├── docker-compose.yml      # Docker Compose 配置
├── alembic.ini             # Alembic 数据库迁移配置
├── pytest.ini              # pytest 配置
├── .flake8                 # flake8 配置
├── .coveragerc             # 测试覆盖率配置
├── .pre-commit-config.yaml # pre-commit 钩子配置
├── sanitize.py             # 数据脱敏工具
├── LICENSE                 # MIT 许可证
└── README.md               # 项目说明
```

### 2.2 核心架构图 (ASCII)

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Layer (Flask)                         │
│  34 Blueprints | 33 Templates | SSE | REST API | Swagger    │
├─────────────────────────────────────────────────────────────┤
│                Security Layer (31 Modules)                   │
│  Firewall | IDS | WAF | VPN | ZTA | SIEM | DDoS | Honeypot │
│  Sandbox | DLP | Antivirus | ARP | Compliance | QoS | ...  │
├─────────────────────────────────────────────────────────────┤
│                 AI Engine (14 Modules)                       │
│  Anomaly | UEBA | Threat Intel | LLM | Traffic Analysis    │
│  Attack Chain | Risk Assessment | Vuln Scan | Prediction    │
├─────────────────────────────────────────────────────────────┤
│                Network Layer (13 Modules)                    │
│  Gateway | Dual WAN | OSPF/BGP | QoS | DHCP | DNS | ...    │
├─────────────────────────────────────────────────────────────┤
│                 Core Infrastructure                         │
│  Database (SQLite/PostgreSQL) | Scheduler | Audit | Logger  │
│  DatabaseManager (Singleton) | Settings (Singleton)         │
└─────────────────────────────────────────────────────────────┘
```

**数据流:**

```
网络流量 -> PacketCapture -> TrafficAnalyzer -> AnomalyDetector
    -> IDS Engine -> AlertManager -> Web/SSE/Email/Webhook
    -> AuditLog -> SIEM Engine -> Dashboard
```

### 2.3 初始化流程

系统启动时，`core/app.py` 中的 `GateKeeper.initialize()` 方法按以下 7 步顺序初始化:

```
[1/7] 初始化数据库          <- CRITICAL, 失败则退出
[2/7] 初始化 AI 引擎        <- WARNING, 失败使用默认模型
[3/7] 初始化网络模块        <- WARNING
[4/7] 初始化告警系统        <- WARNING
[5/7] 初始化 IDS 引擎       <- WARNING
[6/7] 初始化任务调度器      <- WARNING
[7/7] 创建默认管理员        <- WARNING
```

**步骤 1 - 数据库初始化 (CRITICAL):**

```python
# config/database.py
init_db()          # 创建所有表 + 自动迁移缺失列
check_connection() # 验证数据库连接
# 失败时返回 False, 系统退出
```

**步骤 2 - AI 引擎:**

```python
# ai_engine/model_manager.py
ModelManager().load_models()  # 加载 IsolationForest, Scaler, KMeans
# 失败时记录 WARNING, 使用默认模型
```

**步骤 3 - 网络模块:**

```python
# network/packet_capture.py + network/firewall.py
PacketCapture()        # 数据包捕获引擎
FirewallManager()      # iptables 防火墙管理
TrafficAnalyzer()      # 流量分析器 (注册为数据包捕获回调)
packet_capture.register_callback(traffic_analyzer.process_packet)
```

**步骤 4 - 告警系统:**

```python
# alerting/alert_manager.py
AlertManager()  # 邮件/Webhook 告警管理
```

**步骤 5 - IDS 引擎:**

```python
# security/ids_engine.py
get_ids_engine().start()  # 启动入侵检测引擎
```

**步骤 6 - 任务调度器:**

```python
# core/scheduler.py
task_scheduler.register_default_tasks()  # 注册周期性任务
# 包括: 流量分析、异常检测、威胁情报更新、日报生成
```

**步骤 7 - 默认管理员:**

```python
# core/app.py::_create_default_admin()
# 创建 admin-sp (SUPER_ADMIN) 和 admin (ADMIN)
# 密码来源: 环境变量 > 随机生成 (写入 .initial_credentials)
```

### 2.4 单例模式

项目中有 4 个核心单例，均使用线程安全的双重检查锁定模式:

**1. GateKeeper (core/app.py)**

```python
class GateKeeper:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        # ... 初始化代码
```

**2. DatabaseManager (core/database.py)**

```python
class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._engine = engine
        self._session_factory = SessionLocal

# 全局实例
db_manager = DatabaseManager()
```

**3. LogManager (config/logging_config.py)**

```python
class LogManager:
    _instance = None
    _loggers = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._setup_root_logger()
        self._setup_audit_logger()
```

**4. Settings (config/settings.py)**

```python
# Settings 不是严格的单例模式，但作为全局实例使用
settings = Settings()
```

### 2.5 延迟导入机制

`core/app.py` 中定义了 `_lazy_import()` 函数，用于解决模块间的循环依赖问题，并提高启动容错能力。

**函数签名:**

```python
def _lazy_import(module_path, attr_names=None):
    """延迟导入模块，带缓存和异常保护。

    Args:
        module_path: 模块路径，如 'config.database'
        attr_names: 需要从模块中获取的属性名列表

    Returns:
        如果指定了 attr_names，返回属性元组；否则返回模块对象
        导入失败时返回 None 或 (None, None, ...)
    """
```

**设计要点:**

1. **缓存机制**: 使用 `_lazy_modules` 字典缓存已导入的模块，避免重复导入
2. **异常保护**: 导入失败时返回 `None` 而非抛出异常，确保系统可以降级运行
3. **属性提取**: 支持直接从模块中提取指定属性，返回元组

**使用示例:**

```python
# 导入模块
init_db, check_connection = _lazy_import("config.database", ["init_db", "check_connection"])

# 导入单个属性
ModelManager = _lazy_import("ai_engine.model_manager", ["ModelManager"])[0]

# 导入整个模块
ids_mod = _lazy_import("security.ids_engine", ["get_ids_engine"])
get_ids_engine = ids_mod[0] if ids_mod else None
```

---

## 三、配置系统

### 3.1 配置类一览

配置系统位于 `config/settings.py`，包含 7 个配置类和 1 个全局配置管理类:

| 配置类 | 环境变量前缀 | 关键默认值 |
|--------|-------------|-----------|
| `DatabaseConfig` | `GK_DB_` | driver=sqlite, pool_size=10, max_overflow=20 |
| `NetworkConfig` | `GK_NET_` | listen_interface=eth0, buffer_size=256MB, sampling_rate=1.0 |
| `AIModelConfig` | `GK_AI_` | anomaly_threshold=0.85, batch_size=256, epochs=100 |
| `AlertConfig` | `GK_ALERT_` | email_enabled=false, cooldown=300s, max_per_minute=10 |
| `WebConfig` | `GK_WEB_` | host=0.0.0.0, port=8443, ssl=true, session_timeout=60min |
| `LogConfig` | `GK_LOG_` | level=INFO, max_file_size=100MB, backup_count=10 |
| `SchedulerConfig` | `GK_SCHED_` | executor=background, max_workers=10 |

**全局配置类 Settings:**

```python
class Settings(object):
    def __init__(self):
        self.database = DatabaseConfig()
        self.network = NetworkConfig()
        self.ai_model = AIModelConfig()
        self.alert = AlertConfig()
        self.web = WebConfig()
        self.log = LogConfig()
        self.scheduler = SchedulerConfig()
        self.version = "1.0.4"
        self.app_name = "GateKeeper"
        self.instance_name = _env("INSTANCE_NAME", "default")

# 全局单例
settings = Settings()
```

### 3.2 环境变量读取

所有环境变量通过 `_env()` 函数读取，自动添加 `GK_` 前缀:

```python
def _env(key, default="", cast=str):
    """从环境变量读取配置值，支持类型转换"""
    val = os.environ.get("GK_{}".format(key), default)
    if cast == bool:
        return val.lower() in ("true", "1", "yes", "on")
    if cast == int:
        return int(val) if val else default
    if cast == float:
        return float(val) if val else default
    if cast == list:
        return json.loads(val) if val else []
    return val
```

**类型转换规则:**

| cast 参数 | 转换方式 |
|-----------|---------|
| `str` (默认) | 原样返回字符串 |
| `bool` | `"true"/"1"/"yes"/"on"` 转为 `True`, 其他转为 `False` |
| `int` | `int(val)` |
| `float` | `float(val)` |
| `list` | `json.loads(val)` (JSON 数组) |

### 3.3 配置持久化

**导出配置 (脱敏):**

```python
# 导出所有配置 (敏感字段自动脱敏)
config_dict = settings.to_dict()
# password/api_key 等字段会被替换为 "***"
```

**保存到文件:**

```python
# 保存完整配置到 JSON 文件 (包含真实密码)
settings.save_to_file("/path/to/config.json")
```

**从文件加载:**

```python
# 从 JSON 文件加载配置
settings = Settings.load_from_file("/path/to/config.json")
```

**敏感字段脱敏规则:**

以下字段名包含的属性在 `to_dict()` 时会被替换为 `"***"`:

- `password`
- `api_key`
- `secret_key`
- `ssl_key`

脱敏通过各配置类的 `_to_raw_dict(sanitize=True)` 方法实现。

### 3.4 数据库配置

**引擎创建 (config/database.py):**

```python
def get_engine():
    """根据配置自动选择 SQLite 或 PostgreSQL"""
    if settings.database.driver == "sqlite":
        # SQLite 使用 StaticPool 支持多线程
        engine_kwargs["poolclass"] = StaticPool
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # PostgreSQL 使用 QueuePool
        engine_kwargs["poolclass"] = QueuePool
        engine_kwargs["pool_size"] = pool_size
        engine_kwargs["max_overflow"] = max_overflow
```

**会话管理:**

```python
# 方式1: DatabaseManager 上下文管理器 (推荐)
with db_manager.get_session() as session:
    user = session.query(User).first()
    # 自动 commit/rollback/close

# 方式2: 独立上下文管理器
with get_db_session() as session:
    user = session.query(User).first()
    # 自动 commit/rollback/close

# 方式3: 依赖注入 (生成器)
db = get_db()
try:
    # 数据库操作
    db.commit()
finally:
    db.close()

# 方式4: 线程安全 scoped_session
session_factory = get_scoped_session()
```

**数据库初始化与自动迁移:**

```python
def init_db():
    """创建所有表，并自动迁移缺失列"""
    # 导入所有模型注册到 Base.metadata
    from core.models import User, NetworkInterface, FirewallRule, ...
    from security.vpn_service import VPNConfig, VPNClient
    from security.dns_filter import DNSFilterRuleModel, DNSQueryLogModel
    from security.gateway_antivirus import GatewayVirusLog

    Base.metadata.create_all(bind=engine)
    _migrate_missing_columns(engine, Base)  # SQLite 自动迁移
```

`_migrate_missing_columns()` 仅支持 SQLite，通过 `ALTER TABLE ADD COLUMN` 自动添加 ORM 模型中定义但数据库中缺失的列。对于 PostgreSQL，建议使用 Alembic 迁移。

---

## 四、数据模型

### 4.1 枚举类型

所有枚举定义在 `core/models.py` 中:

| 枚举类型 | 值 | 说明 |
|---------|-----|------|
| `UserRole` | `SUPER_ADMIN`, `ADMIN`, `OPERATOR`, `VIEWER` | 用户角色 (大写值) |
| `AlertLevel` | `low`, `medium`, `high`, `critical` | 告警级别 |
| `AlertStatus` | `new`, `acknowledged`, `resolved`, `ignored` | 告警状态 |
| `VulnSeverity` | `info`, `low`, `medium`, `high`, `critical` | 漏洞严重程度 |
| `ScanStatus` | `pending`, `running`, `completed`, `failed`, `cancelled` | 扫描状态 |
| `FirewallAction` | `accept`, `drop`, `reject`, `log` | 防火墙动作 |
| `ProtocolType` | `tcp`, `udp`, `icmp`, `any` | 协议类型 |
| `ThreatLevel` | `low`, `medium`, `high`, `critical` | 威胁级别 |
| `AttackType` | `sql_injection`, `xss`, `path_traversal`, `command_injection`, `brute_force`, `port_scan`, `exploit`, `malicious_tool`, `dos`, `other` | 攻击类型 |
| `AttackSeverity` | `low`, `medium`, `high`, `critical` | 攻击严重程度 |

> **注意**: `UserRole` 使用大写值 (`SUPER_ADMIN`)，其他枚举使用小写值 (`low`)。在数据库比较时需要注意大小写匹配。

### 4.2 模型关系图 (ASCII)

```
User --1:N--> Alert (assigned_to)
User --1:N--> FirewallRule (created_by)
User --1:N--> ScanResult (created_by)

NetworkInterface --1:N--> TrafficLog (interface_id)

ScanResult --1:N--> Vulnerability (scan_id)

DHCPSubnet --1:N--> DHCPLease (subnet_id)

VPNConfig --1:N--> VPNClient (config_id)
```

### 4.3 模型详细说明

#### User (用户表)

- **表名**: `users`
- **说明**: 管理系统用户，支持 Flask-Login 认证

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK, autoincrement | 主键 |
| `username` | String(64) | unique, not null, index | 用户名 |
| `email` | String(128) | unique, nullable | 邮箱 |
| `password_hash` | String(256) | not null | 密码哈希 |
| `role` | Enum(UserRole) | not null, default=VIEWER | 角色 |
| `is_active` | Boolean | not null, default=True | 是否启用 |
| `last_login` | DateTime | nullable | 最后登录时间 |
| `login_attempts` | Integer | not null, default=0 | 登录尝试次数 |
| `locked_until` | DateTime | nullable | 锁定截止时间 |
| `must_change_password` | Boolean | not null, default=False | 是否需要修改密码 |
| `created_at` | DateTime | not null, server_default=now() | 创建时间 |
| `updated_at` | DateTime | not null, server_default=now() | 更新时间 |

**关系**: `alerts` -> Alert, `firewall_rules` -> FirewallRule

---

#### NetworkInterface (网络接口表)

- **表名**: `network_interfaces`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `name` | String(64) | unique, not null | 接口名称 |
| `ip_address` | String(45) | nullable | IP 地址 |
| `netmask` | String(45) | nullable | 子网掩码 |
| `mac_address` | String(17) | nullable | MAC 地址 |
| `interface_type` | String(32) | not null, default="ethernet" | 接口类型 |
| `is_monitoring` | Boolean | not null, default=False | 是否监控 |
| `is_up` | Boolean | not null, default=False | 是否启用 |
| `speed_mbps` | Integer | nullable | 速度 (Mbps) |
| `mtu` | Integer | not null, default=1500 | MTU |
| `rx_packets` | BigInteger | not null, default=0 | 接收包数 |
| `tx_packets` | BigInteger | not null, default=0 | 发送包数 |
| `rx_bytes` | BigInteger | not null, default=0 | 接收字节数 |
| `tx_bytes` | BigInteger | not null, default=0 | 发送字节数 |
| `rx_errors` | BigInteger | not null, default=0 | 接收错误数 |
| `tx_errors` | BigInteger | not null, default=0 | 发送错误数 |
| `last_seen` | DateTime | not null, server_default=now() | 最后发现时间 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

**关系**: `traffic_logs` -> TrafficLog

---

#### FirewallRule (防火墙规则表)

- **表名**: `firewall_rules`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `name` | String(128) | not null | 规则名称 |
| `description` | Text | nullable | 描述 |
| `chain` | String(32) | not null, default="INPUT" | iptables 链 |
| `protocol` | Enum(ProtocolType) | not null, default=ANY | 协议 |
| `source_ip` | String(45) | nullable | 源 IP |
| `source_port` | Integer | nullable | 源端口 |
| `dest_ip` | String(45) | nullable | 目的 IP |
| `dest_port` | Integer | nullable | 目的端口 |
| `action` | Enum(FirewallAction) | not null, default=DROP | 动作 |
| `is_enabled` | Boolean | not null, default=True | 是否启用 |
| `priority` | Integer | not null, default=100 | 优先级 |
| `hit_count` | BigInteger | not null, default=0 | 命中次数 |
| `created_by` | Integer | FK(users.id), nullable | 创建者 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

**关系**: `created_by_user` -> User

---

#### TrafficLog (流量日志表)

- **表名**: `traffic_logs`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `timestamp` | DateTime | not null, index | 时间戳 |
| `interface_id` | Integer | FK(network_interfaces.id), nullable | 网络接口 |
| `source_ip` | String(45) | not null, index | 源 IP |
| `dest_ip` | String(45) | not null, index | 目的 IP |
| `source_port` | Integer | nullable | 源端口 |
| `dest_port` | Integer | nullable | 目的端口 |
| `protocol` | String(16) | not null | 协议 |
| `packet_length` | Integer | not null | 包长度 |
| `flags` | String(32) | nullable | TCP 标志 |
| `ttl` | Integer | nullable | TTL |
| `is_anomaly` | Boolean | not null, default=False, index | 是否异常 |
| `anomaly_score` | Float | nullable | 异常分数 |
| `threat_label` | String(64) | nullable | 威胁标签 |
| `raw_packet` | LargeBinary | nullable | 原始数据包 |

**索引**: `idx_traffic_src_dst(source_ip, dest_ip)`, `idx_traffic_timestamp_proto(timestamp, protocol)`

**关系**: `interface` -> NetworkInterface

---

#### Alert (告警表)

- **表名**: `alerts`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `title` | String(256) | not null | 标题 |
| `description` | Text | nullable | 描述 |
| `level` | Enum(AlertLevel) | not null, index | 级别 |
| `status` | Enum(AlertStatus) | not null, index | 状态 |
| `source` | String(64) | not null | 来源 (ids/vuln_scanner/firewall/ai_engine) |
| `source_ip` | String(45) | nullable | 源 IP |
| `dest_ip` | String(45) | nullable | 目的 IP |
| `port` | Integer | nullable | 端口 |
| `protocol` | String(16) | nullable | 协议 |
| `severity_score` | Float | nullable | 严重度分数 |
| `assigned_to` | Integer | FK(users.id), nullable | 指派给 |
| `resolved_at` | DateTime | nullable | 解决时间 |
| `resolution_note` | Text | nullable | 解决备注 |
| `metadata_json` | JSON | nullable | 元数据 |
| `created_at` | DateTime | not null, index | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

**关系**: `assigned_user` -> User

---

#### Vulnerability (漏洞表)

- **表名**: `vulnerabilities`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `scan_id` | Integer | FK(scan_results.id), nullable | 扫描结果 |
| `host` | String(45) | not null, index | 主机 |
| `port` | Integer | nullable | 端口 |
| `service` | String(128) | nullable | 服务 |
| `name` | String(256) | not null | 漏洞名称 |
| `description` | Text | nullable | 描述 |
| `severity` | Enum(VulnSeverity) | not null, index | 严重程度 |
| `cve_id` | String(32) | nullable | CVE 编号 |
| `cvss_score` | Float | nullable | CVSS 分数 |
| `solution` | Text | nullable | 修复方案 |
| `references` | JSON | nullable | 参考资料 |
| `is_confirmed` | Boolean | not null, default=False | 是否确认 |
| `is_fixed` | Boolean | not null, default=False | 是否修复 |
| `fixed_at` | DateTime | nullable | 修复时间 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

---

#### IDSRule (IDS 规则表)

- **表名**: `ids_rules`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `rule_id` | String(64) | unique, not null | 规则唯一标识 |
| `name` | String(256) | not null | 规则名称 |
| `description` | Text | nullable | 描述 |
| `category` | String(64) | nullable | 分类 |
| `protocol` | String(16) | nullable | 协议 |
| `source_ip` | String(45) | nullable | 源 IP |
| `source_port` | String(64) | nullable | 源端口 |
| `dest_ip` | String(45) | nullable | 目的 IP |
| `dest_port` | String(64) | nullable | 目的端口 |
| `pattern` | Text | nullable | 匹配模式/正则 |
| `pattern_type` | String(32) | not null, default="regex" | 模式类型 (regex/pcre/content) |
| `is_enabled` | Boolean | not null, default=True | 是否启用 |
| `confidence` | Float | not null, default=0.8 | 置信度 |
| `hit_count` | BigInteger | not null, default=0 | 命中次数 |
| `last_hit` | DateTime | nullable | 最后命中时间 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

---

#### ScanResult (扫描结果表)

- **表名**: `scan_results`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `scan_type` | String(64) | not null | 扫描类型 (vuln_scan/port_scan/service_scan) |
| `target` | String(256) | not null | 扫描目标 |
| `status` | Enum(ScanStatus) | not null, index | 状态 |
| `started_at` | DateTime | nullable | 开始时间 |
| `completed_at` | DateTime | nullable | 完成时间 |
| `total_hosts` | Integer | not null, default=0 | 总主机数 |
| `scanned_hosts` | Integer | not null, default=0 | 已扫描主机数 |
| `total_vulns` | Integer | not null, default=0 | 总漏洞数 |
| `critical_vulns` | Integer | not null, default=0 | 严重漏洞数 |
| `high_vulns` | Integer | not null, default=0 | 高危漏洞数 |
| `medium_vulns` | Integer | not null, default=0 | 中危漏洞数 |
| `low_vulns` | Integer | not null, default=0 | 低危漏洞数 |
| `scan_options` | JSON | nullable | 扫描选项 |
| `error_message` | Text | nullable | 错误信息 |
| `created_by` | Integer | FK(users.id), nullable | 创建者 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

**关系**: `vulnerabilities` -> Vulnerability

---

#### SystemConfig (系统配置表)

- **表名**: `system_configs`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `category` | String(64) | not null, index | 配置分类 |
| `key` | String(128) | not null | 配置键 |
| `value` | Text | not null | 配置值 |
| `value_type` | String(32) | not null, default="string" | 值类型 (string/int/float/bool/json) |
| `description` | Text | nullable | 描述 |
| `is_readonly` | Boolean | not null, default=False | 是否只读 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

**索引**: `idx_config_category_key(category, key)` (unique)

**方法**: `get_typed_value()` 根据 `value_type` 返回正确类型的值

---

#### DHCPSubnet (DHCP 子网配置表)

- **表名**: `dhcp_subnets`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `name` | String(64) | not null | 子网名称 |
| `network` | String(18) | not null | 网络地址 (如 192.168.1.0/24) |
| `gateway` | String(45) | not null | 网关地址 |
| `start_ip` | String(45) | not null | DHCP 起始 IP |
| `end_ip` | String(45) | not null | DHCP 结束 IP |
| `lease_time` | Integer | not null, default=86400 | 租约时间 (秒) |
| `dns_servers` | String(255) | nullable | DNS 服务器 (逗号分隔) |
| `interface` | String(32) | not null | 绑定接口 |
| `vlan_id` | Integer | nullable | VLAN ID (1-4094) |
| `vlan_interface` | String(32) | nullable | VLAN 接口名 |
| `is_enabled` | Boolean | not null, default=True | 是否启用 |
| `priority` | Integer | not null, default=100 | 优先级 |
| `description` | Text | nullable | 描述 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

**索引**: `idx_dhcp_subnet_vlan(vlan_id)`, `idx_dhcp_subnet_interface(interface)`

---

#### DHCPLease (DHCP 租约记录表)

- **表名**: `dhcp_leases`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `subnet_id` | Integer | FK(dhcp_subnets.id), not null | 子网 |
| `mac_address` | String(17) | not null, index | MAC 地址 |
| `ip_address` | String(45) | not null, index | 分配的 IP |
| `hostname` | String(64) | nullable | 主机名 |
| `lease_start` | DateTime | not null, server_default=now() | 租约开始 |
| `lease_end` | DateTime | not null | 租约到期 |
| `is_active` | Boolean | not null, default=True | 是否活跃 |
| `client_id` | String(64) | nullable | 客户端标识 |

**关系**: `subnet` -> DHCPSubnet

---

#### ThreatIntel (威胁情报表)

- **表名**: `threat_intel`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `indicator_type` | String(32) | not null | 指标类型 (ip/domain/url/hash/email) |
| `indicator_value` | String(512) | not null, index | 指标值 |
| `threat_type` | String(64) | nullable | 威胁类型 (malware/phishing/c2/botnet/spam) |
| `threat_level` | Enum(ThreatLevel) | not null, index | 威胁级别 |
| `confidence` | Float | not null, default=0.5 | 置信度 |
| `source` | String(128) | not null | 情报来源 |
| `description` | Text | nullable | 描述 |
| `affected_systems` | JSON | nullable | 受影响系统 |
| `ioc_data` | JSON | nullable | 入侵指标数据 |
| `first_seen` | DateTime | nullable | 首次发现 |
| `last_seen` | DateTime | nullable | 最后发现 |
| `is_active` | Boolean | not null, default=True | 是否活跃 |
| `expires_at` | DateTime | nullable | 过期时间 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

---

#### AttackLog (攻击日志表)

- **表名**: `attack_logs`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `timestamp` | DateTime | not null, index | 时间戳 |
| `src_ip` | String(45) | not null, index | 源 IP |
| `dst_ip` | String(45) | not null | 目的 IP |
| `dst_port` | Integer | nullable | 目的端口 |
| `attack_type` | Enum(AttackType) | not null, index | 攻击类型 |
| `severity` | Enum(AttackSeverity) | not null, index | 严重程度 |
| `signature` | String(256) | not null | 匹配签名名称 |
| `description` | Text | nullable | 描述 |
| `payload_preview` | Text | nullable | 载荷预览 |
| `protocol` | String(16) | nullable | 协议 |
| `is_blocked` | Boolean | not null, default=False | 是否已阻断 |
| `block_reason` | String(256) | nullable | 阻断原因 |

**索引**: `idx_attack_src_time(src_ip, timestamp)`, `idx_attack_type_severity(attack_type, severity)`

---

#### AuditLog (操作审计日志表)

- **表名**: `audit_logs`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `timestamp` | DateTime | not null, index | 时间戳 |
| `source` | String(16) | not null, index | 来源 (web/cli/api/system) |
| `username` | String(64) | nullable, index | 操作用户 |
| `action` | String(64) | not null, index | 操作类型 |
| `module` | String(64) | nullable, index | 功能模块 |
| `detail` | Text | nullable | 操作详情 |
| `client_ip` | String(45) | nullable, index | 客户端 IP |
| `user_agent` | String(256) | nullable | 浏览器 UA |
| `result` | String(16) | not null, default="success" | 结果 (success/failure) |
| `error_message` | Text | nullable | 失败原因 |
| `request_data` | Text | nullable | 请求数据 (JSON) |

**索引**: `idx_audit_source_time(source, timestamp)`, `idx_audit_user_action(username, action)`

---

#### VPNConfig (VPN 配置表)

- **表名**: `vpn_configs`
- **定义位置**: `security/vpn_service.py`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `name` | String(128) | unique, not null | 名称 |
| `vpn_type` | String(32) | not null | 类型 (wireguard/ipsec/openvpn) |
| `server_ip` | String(45) | not null | 服务器 IP |
| `server_port` | Integer | not null | 服务器端口 |
| `client_ip_range` | String(45) | not null | 客户端 IP 范围 |
| `dns_servers` | Text | nullable | DNS 服务器 (JSON) |
| `allowed_users` | Text | nullable | 允许用户 (JSON) |
| `enabled` | Boolean | not null, default=False | 是否启用 |
| `mtu` | Integer | not null, default=1420 | MTU |
| `keepalive` | Integer | not null, default=25 | Keepalive 间隔 |
| `config_text` | Text | nullable | 完整配置文件 |
| `created_at` | DateTime | not null | 创建时间 |
| `updated_at` | DateTime | not null | 更新时间 |

**关系**: `clients` -> VPNClient

---

#### VPNClient (VPN 客户端表)

- **表名**: `vpn_clients`
- **定义位置**: `security/vpn_service.py`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `config_id` | Integer | FK(vpn_configs.id), not null | VPN 配置 |
| `username` | String(128) | not null | 用户名 |
| `public_key` | Text | nullable | WireGuard 公钥 |
| `assigned_ip` | String(45) | nullable | 分配 IP |
| `connected` | Boolean | not null, default=False | 是否连接 |
| `last_connected` | DateTime | nullable | 最后连接时间 |
| `bytes_sent` | BigInteger | not null, default=0 | 发送字节 |
| `bytes_received` | BigInteger | not null, default=0 | 接收字节 |

**关系**: `config` -> VPNConfig

---

#### DNSFilterRuleModel (DNS 过滤规则表)

- **表名**: `dns_filter_rules`
- **定义位置**: `security/dns_filter.py`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `name` | String(128) | not null | 规则名称 |
| `domain` | String(256) | not null, index | 域名 |
| `rule_type` | String(32) | not null, default="blacklist" | 类型 (whitelist/blacklist/category) |
| `category` | String(64) | nullable | 分类 (adult/gambling/malware/phishing/...) |
| `action` | String(32) | not null, default="block" | 动作 (block/redirect/sinkhole) |
| `redirect_to` | String(45) | nullable | 重定向 IP |
| `enabled` | Boolean | not null, default=True | 是否启用 |
| `hit_count` | BigInteger | not null, default=0 | 命中次数 |
| `description` | Text | nullable | 描述 |
| `created_at` | DateTime | not null | 创建时间 |

**索引**: `idx_dns_rule_type_enabled(rule_type, enabled)`, `idx_dns_category(category)`

---

#### DNSQueryLogModel (DNS 查询日志表)

- **表名**: `dns_query_logs`
- **定义位置**: `security/dns_filter.py`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `timestamp` | DateTime | not null | 时间戳 |
| `client_ip` | String(45) | not null | 客户端 IP |
| `domain` | String(256) | not null | 查询域名 |
| `query_type` | String(16) | nullable | 查询类型 (A/AAAA/MX/...) |
| `action` | String(32) | nullable | 执行动作 |
| `rule_matched` | String(128) | nullable | 匹配规则 |
| `response_ip` | String(45) | nullable | 响应 IP |

---

#### GatewayVirusLog (网关病毒扫描日志表)

- **表名**: `gateway_virus_logs`
- **定义位置**: `security/gateway_antivirus.py`

| 列名 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | Integer | PK | 主键 |
| `timestamp` | DateTime | server_default=now() | 时间戳 |
| `protocol` | String(20) | nullable | 协议 (http/ftp/smtp/smb) |
| `src_ip` | String(45) | nullable | 源 IP |
| `dst_ip` | String(45) | nullable | 目的 IP |
| `src_port` | Integer | nullable | 源端口 |
| `dst_port` | Integer | nullable | 目的端口 |
| `file_name` | String(255) | nullable | 文件名 |
| `file_size` | Integer | nullable | 文件大小 |
| `virus_name` | String(255) | nullable | 病毒名称 |
| `action` | String(20) | nullable | 动作 (blocked/passed/error) |
| `scanner` | String(50) | nullable | 扫描器 (clamav/builtin) |
| `details` | Text | nullable | 详情 |

### 4.4 数据库会话使用模式

**推荐模式 - 使用 DatabaseManager 上下文管理器:**

```python
from core.database import db_manager
from core.models import User

# 自动处理 commit/rollback/close
with db_manager.get_session() as session:
    user = session.query(User).filter_by(username="admin").first()
    user.last_login = datetime.now()
    # 退出 with 块时自动 commit
```

**防止 DetachedInstanceError:**

```python
with db_manager.get_session() as session:
    user = session.query(User).filter_by(username="admin").first()
    session.expunge(user)  # 在关闭 session 前分离对象
# 现在 user 对象可以在 session 外安全访问属性
print(user.username)
```

**使用 DatabaseManager 的 CRUD 方法:**

```python
from core.database import db_manager
from core.models import User

# 添加
user = db_manager.add(User(username="test", ...))

# 按 ID 查询
user = db_manager.get_by_id(User, 1)

# 分页查询
users = db_manager.get_all(User, limit=10, offset=0)

# 统计
count = db_manager.count(User)

# 删除
db_manager.delete(User, user_id=1)
```

---

## 五、Web 应用开发

### 5.1 应用工厂

`web/app.py` 中的 `create_web_app()` 函数是 Flask 应用的工厂方法，执行以下初始化步骤:

1. **创建 Flask 实例**: 指定 `template_folder` 和 `static_folder`
2. **SECRET_KEY 自动生成**: 如果未配置或使用默认值，自动生成随机密钥并持久化到 `data/.secret_key`
3. **Session 安全配置**: `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE=Lax`
4. **CSRF 初始化**: `Flask-WTF CSRFProtect` 启用，token 有效期 1 小时
5. **扩展初始化**: Flask-Limiter (速率限制), Flask-Login (认证)
6. **蓝图注册**: 注册 34 个蓝图 (容错模式，单个失败不影响整体)
7. **错误处理器**: 404, 500, 403, 429 (区分 API 和 HTML 请求)
8. **上下文处理器**: 注入全局变量 (version) 到模板
9. **CSRF 豁免**: `auth_bp` (整个蓝图), `api_change_password` (单个路由)
10. **Swagger 文档**: 访问 `/apidocs` 查看 API 文档 (依赖 flasgger)
11. **数据库初始化**: 调用 `init_db()` 确保表存在
12. **Shutdown 路由**: `/shutdown` (仅限 127.0.0.1 访问，需 admin 权限)

### 5.2 蓝图列表

项目共注册 34 个蓝图:

| 蓝图名 | URL 前缀 | 模块路径 | 说明 |
|--------|---------|---------|------|
| `dashboard_bp` | `/` | `web.routes.dashboard` | 仪表盘 |
| `alerts_bp` | `/alerts` | `web.routes.alerts` | 告警管理 |
| `reports_bp` | `/reports` | `web.routes.reports` | 报告管理 |
| `network_bp` | `/network` | `web.routes.network` | 网络管理 |
| `settings_bp` | `/settings` | `web.routes.settings` | 系统设置 |
| `auth_bp` | `/auth` | `web.routes.auth` | 认证 (CSRF 豁免) |
| `ids_bp` | `/ids` | `web.routes.ids` | IDS 管理 |
| `gateway_bp` | `/gateway` | `web.routes.gateway` | 网关管理 |
| `audit_bp` | `/audit` | `web.routes.audit` | 审计日志 |
| `honeypot_bp` | `/honeypot` | `web.routes.honeypot` | 蜜罐管理 |
| `vuln_scan_bp` | `/vuln-scan` | `web.routes.vuln_scan` | 漏洞扫描 |
| `waf_bp` | `/waf` | `web.routes.waf` | WAF 管理 |
| `vpn_bp` | `/vpn` | `web.routes.vpn` | VPN 管理 |
| `qos_bp` | `/qos` | `web.routes.qos` | QoS 管理 |
| `dns_filter_bp` | `/dns-filter` | `web.routes.dns_filter` | DNS 过滤 |
| `isolation_bp` | `/isolation` | `web.routes.isolation` | 网络隔离 |
| `compliance_bp` | `/compliance` | `web.routes.compliance` | 合规管理 |
| `assets_bp` | `/assets` | `web.routes.assets` | 资产管理 |
| `ddos_bp` | `/ddos` | `web.routes.ddos` | DDoS 防护 |
| `siem_bp` | `/siem` | `web.routes.siem` | SIEM 管理 |
| `ntconfig_bp` | `/ntconfig` | `web.routes.ntconfig` | NT 配置检查 |
| `dual_wan_bp` | `/dual-wan` | `web.routes.dual_wan` | 双 WAN 管理 |
| `routing_bp` | `/routing` | `web.routes.routing` | 路由管理 |
| `rule_update_bp` | `/rule-update` | `web.routes.rule_update` | 规则更新 |
| `app_control_bp` | `/app-control` | `web.routes.app_control` | 应用控制 |
| `content_security_bp` | `/content-security` | `web.routes.content_security` | 内容安全 |
| `ha_bp` | `/ha` | `web.routes.ha` | 高可用管理 |
| `gateway_av_bp` | `/gateway_av` | `web.routes.gateway_av` | 网关防病毒 |
| `ssl_bp` | `/ssl` | `web.routes.ssl_inspector` | SSL 检查 |
| `zta_bp` | `/zta` | `web.routes.zero_trust` | 零信任 |
| `ldap_bp` | `/ldap` | `web.routes.auth_ldap` | LDAP 认证 |
| `sandbox_bp` | `/sandbox` | `web.routes.sandbox` | 沙箱分析 |
| `health_bp` | (无) | `web.routes.health` | 健康检查 |
| `ws_bp` | (无) | `web.routes.websocket` | WebSocket/SSE |

### 5.3 API 路由规范

**路由装饰器模式:**

```python
from flask import Blueprint, jsonify, request
from web.routes.auth import login_required, admin_required

my_bp = Blueprint("my_module", __name__)

@my_bp.route("/api/my_data", methods=["GET"])
@login_required
def api_get_my_data():
    """获取数据"""
    data = request.json if request.is_json else {}
    try:
        with db_manager.get_session() as session:
            # 业务逻辑
            result = session.query(MyModel).all()
            return jsonify({
                "status": "ok",
                "data": [{"id": r.id, "name": r.name} for r in result]
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@my_bp.route("/api/my_data", methods=["POST"])
@login_required
@admin_required
def api_create_my_data():
    """创建数据"""
    data = request.json if request.is_json else {}
    try:
        with db_manager.get_session() as session:
            obj = MyModel(name=data.get("name", ""))
            session.add(obj)
            return jsonify({"status": "ok", "data": {"id": obj.id}})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
```

**响应格式规范:**

成功响应:
```json
{
    "status": "ok",
    "data": { ... }
}
```

错误响应:
```json
{
    "status": "error",
    "message": "错误描述"
}
```

分页响应:
```json
{
    "status": "ok",
    "data": {
        "items": [ ... ],
        "total": 100,
        "page": 1,
        "per_page": 20
    }
}
```

### 5.4 认证与权限

**权限装饰器 (web/routes/auth.py):**

```python
# login_required - Flask-Login 标准装饰器，要求用户已登录
@login_required
def my_view():
    pass

# admin_required - 允许 ADMIN 和 SUPER_ADMIN 角色
@admin_required
def admin_view():
    pass

# super_admin_required - 仅允许 SUPER_ADMIN 角色
@super_admin_required
def super_admin_view():
    pass
```

**登录流程:**

```
用户提交密码 -> 验证用户名/密码
    -> 检查账户锁定 (5次失败锁定30分钟)
    -> 检查 2FA 状态
        -> 启用 2FA: 返回 2FA 临时令牌
        -> 未启用: 检查 must_change_password
            -> 需要修改: 返回 must_change_password
            -> 不需要: login_user() 登录成功
```

**Session 安全配置:**

```python
app.config["SESSION_COOKIE_SECURE"] = True   # 仅 HTTPS 传输
app.config["SESSION_COOKIE_HTTPONLY"] = True  # 禁止 JavaScript 访问
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" # CSRF 防护
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 60 分钟超时
```

**账户锁定策略:**

- 最大尝试次数: `GK_WEB_MAX_LOGIN_ATTEMPTS` (默认 5)
- 锁定时间: `GK_WEB_LOGIN_LOCKOUT` (默认 30 分钟)
- 锁定后返回 403 状态码和剩余锁定时间

**密码策略:**

- 最少 8 个字符
- 必须包含大写字母
- 必须包含小写字母
- 必须包含数字
- 必须包含特殊字符
- 使用 `werkzeug.security.generate_password_hash` / `check_password_hash`

### 5.5 CSRF 保护

项目使用 Flask-WTF CSRFProtect，默认对所有 POST 路由启用 CSRF 保护。

**豁免路由:**

- `auth_bp` (整个蓝图): 登录前无法获取 CSRF token
- `api_change_password` (单个路由): 首次登录修改密码时无法获取 CSRF token

**前端 AJAX 请求:**

```javascript
// 获取 CSRF Token
function getCsrfToken() {
    // 从 meta 标签或 cookie 中获取
    var metas = document.getElementsByTagName('meta');
    for (var i = 0; i < metas.length; i++) {
        if (metas[i].getAttribute('name') === 'csrf-token') {
            return metas[i].getAttribute('content');
        }
    }
    return null;
}

// 发送 AJAX 请求
fetch('/api/data', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken()
    },
    body: JSON.stringify(data)
});
```

### 5.6 速率限制

项目使用 Flask-Limiter (可选依赖) 实现速率限制:

| 路由 | 限制 | 说明 |
|------|------|------|
| 全局 | `200 per minute` | 默认限制 |
| `/auth/login` | `5 per minute` | 登录接口 |
| `/auth/verify_2fa` | `10 per minute` | 2FA 验证接口 |

**实现方式:**

```python
# web/app.py::_init_limiter()
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute"],
)

# 对特定路由设置限制
app.limiter.limit("5 per minute")(auth_bp.view_functions['login'])
```

> 如果 `flask_limiter` 未安装，系统会跳过速率限制配置并记录 WARNING 日志。

### 5.7 错误处理

**API vs HTML 错误响应:**

系统通过 `_is_api_request()` 判断请求类型，返回不同格式的错误响应:

```python
def _is_api_request():
    """判断是否为 API 请求"""
    return request.path.startswith('/api/') or request.is_json
```

**错误码处理:**

| HTTP 状态码 | API 响应 | HTML 响应 |
|------------|---------|----------|
| 404 | `{"status": "error", "message": "资源未找到"}` | 渲染 404 模板 |
| 500 | `{"status": "error", "message": "操作失败（错误码: xxxxxxxx）"}` | 渲染 500 模板 |
| 403 | `{"status": "error", "message": "访问被拒绝"}` | 渲染 403 模板 |
| 429 | `{"status": "error", "message": "请求过于频繁", "retry_after": ...}` | 渲染 429 模板 |

**安全错误消息:**

```python
def _safe_error_message(error):
    """生成安全的错误消息，不泄露内部信息"""
    error_id = uuid.uuid4().hex[:8]
    logger.error("请求处理失败 [%s]: %s", error_id, str(error), exc_info=True)
    return {
        "status": "error",
        "message": "操作失败，请联系管理员（错误码: {}）".format(error_id)
    }
```

### 5.8 实时推送 (SSE)

项目通过 `websocket_bp` 蓝图提供 Server-Sent Events (SSE) 实时推送:

**端点**: `/events`

```javascript
// 前端 SSE 连接
var eventSource = new EventSource('/events');

eventSource.addEventListener('alert', function(event) {
    var data = JSON.parse(event.data);
    console.log('新告警:', data);
    // 更新 UI
});

eventSource.addEventListener('traffic', function(event) {
    var data = JSON.parse(event.data);
    console.log('流量更新:', data);
});

eventSource.onerror = function() {
    // 自动重连
    console.log('SSE 连接断开，正在重连...');
};
```

### 5.9 添加新蓝图指南

**步骤 1 - 创建路由文件:**

```python
# web/routes/my_module.py
from flask import Blueprint, jsonify, request, render_template
from web.routes.auth import login_required, admin_required
from core.database import db_manager

my_bp = Blueprint("my_module", __name__)

@my_bp.route("/my-module")
@login_required
def index():
    """页面路由"""
    return render_template("my_module.html", title="我的模块")

@my_bp.route("/api/my-module/data", methods=["GET"])
@login_required
def api_get_data():
    """API 路由"""
    try:
        with db_manager.get_session() as session:
            # 业务逻辑
            return jsonify({"status": "ok", "data": []})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
```

**步骤 2 - 在应用工厂中注册蓝图:**

在 `web/app.py` 的 `_register_blueprints()` 函数中添加:

```python
_blueprint_defs = [
    # ... 已有蓝图 ...
    ("my_module", "/my-module", "web.routes.my_module", "my_bp"),
]
```

**步骤 3 - 创建模板文件:**

```html
<!-- web/templates/my_module.html -->
{% extends "base.html" %}
{% block content %}
<div class="container">
    <h2>我的模块</h2>
    <!-- 页面内容 -->
</div>
{% endblock %}
```

**步骤 4 - 添加导航链接:**

在 `web/templates/base.html` 的导航栏中添加链接:

```html
<a href="/my-module" class="nav-link">我的模块</a>
```

---

## 六、安全模块开发

### 6.1 模块概览

`security/` 目录包含 31 个安全功能模块:

| 模块文件 | 主要类/函数 | 说明 |
|---------|------------|------|
| `ids_engine.py` | `IDSEngine`, `AttackSignature` | 入侵检测引擎 (IDS/IPS) |
| `firewall.py` | `SecurityFirewall` | 安全防火墙策略管理 (iptables) |
| `waf_engine.py` | `WAFEngine` | Web 应用防火墙 |
| `vpn_service.py` | `VPNService`, `VPNConfig`, `VPNClient` | VPN 服务管理 |
| `ddos_protector.py` | `DDoSProtector` | DDoS 防护 |
| `honeypot.py` | `HoneypotManager` | 蜜罐系统 |
| `sandbox_analyzer.py` | `SandboxAnalyzer` | 沙箱分析 |
| `siem_engine.py` | `SIEMEngine` | SIEM 安全信息与事件管理 |
| `zero_trust.py` | `ZeroTrustManager` | 零信任架构 |
| `gateway_antivirus.py` | `GatewayAntivirusEngine` | 网关级防病毒 |
| `dns_filter.py` | `DNSFilterEngine` | DNS 过滤引擎 |
| `ssl_inspector.py` | `SSLInspector` | SSL/TLS 检查 |
| `ssl_checker.py` | `SSLChecker` | SSL 证书检查 |
| `vuln_scanner.py` | `VulnerabilityScanner` | 漏洞扫描 |
| `network_scanner.py` | `NetworkScanner` | 网络扫描 |
| `asset_discovery.py` | `AssetDiscovery` | 资产发现 |
| `arp_protection.py` | `ARPProtection` | ARP 防护 |
| `mac_manager.py` | `MACManager` | MAC 地址管理 |
| `network_isolation.py` | `NetworkIsolation` | 网络隔离 |
| `bandwidth_manager.py` | `BandwidthManager` | 带宽管理 |
| `qos_manager.py` | `QoSManager` | QoS 服务质量管理 |
| `content_security.py` | `ContentSecurity` | 内容安全 |
| `compliance_checker.py` | `ComplianceChecker` | 合规检查 |
| `two_factor.py` | `TwoFactorAuth` | 双因素认证 (2FA) |
| `auth_ldap.py` | `LDAPAuth` | LDAP/AD 认证 |
| `ha_manager.py` | `HAManager` | 高可用管理 |
| `rule_updater.py` | `RuleUpdater` | 规则更新器 |
| `app_detector.py` | `AppDetector` | 应用层检测 |
| `dhcp_monitor.py` | `DHCPMonitor` | DHCP 监控 |
| `protocol_scanners.py` | `ProtocolScanners` | 协议扫描器 |
| `ntconfig_checker.py` | `NTConfigChecker` | Windows NT 配置检查 |

### 6.2 模块开发规范

**类设计模式:**

```python
"""security/my_module.py - 模块说明"""
from config.logging_config import get_logger
from core.database import db_manager

logger = get_logger("my_module")

class MySecurityModule:
    """安全模块类"""

    def __init__(self):
        self._enabled = True
        logger.info("安全模块初始化完成")

    def execute(self, **kwargs):
        """执行安全操作"""
        try:
            # 业务逻辑
            logger.info("操作执行成功")
            return {"status": "ok"}
        except Exception as e:
            logger.error("操作执行失败: {}".format(e))
            return {"status": "error", "message": str(e)}
```

**关键规范:**

1. **日志**: 使用 `get_logger("module_name")` 获取日志记录器
2. **数据库**: 通过 `db_manager.get_session()` 获取会话
3. **配置**: 通过 `SystemConfig` 表或 `settings` 对象读取配置
4. **错误处理**: 捕获所有异常，记录日志，返回安全错误消息
5. **单例**: 如需单例，使用线程安全的 `__new__` + `_initialized` 模式

### 6.3 IDS 引擎开发

`security/ids_engine.py` 实现了完整的入侵检测与防御引擎:

**攻击签名定义:**

```python
class AttackSignature:
    """攻击特征签名"""
    def __init__(self, name: str, pattern: str, attack_type: AttackType,
                 severity: AttackSeverity, description: str):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.attack_type = attack_type
        self.severity = severity
        self.description = description
```

**内置签名类型:**

- SQL 注入 (Union 查询, Error Based)
- XSS 跨站脚本 (Script Tag)
- 路径遍历 (../)
- 命令注入 (; | ` $())
- 暴力破解
- 端口扫描
- 恶意工具检测
- DoS 攻击

**IDS 引擎核心方法:**

```python
class IDSEngine:
    def __init__(self, auto_block=False):
        self.auto_block = auto_block  # 是否自动阻断

    def start(self):
        """启动 IDS 引擎"""

    def stop(self):
        """停止 IDS 引擎"""

    def analyze_packet(self, packet_data):
        """分析数据包"""

    def check_signature(self, payload):
        """检查攻击签名"""

    def ban_ip(self, ip_address, duration=3600, reason=""):
        """封禁 IP"""

    def unban_ip(self, ip_address):
        """解封 IP"""
```

### 6.4 防火墙规则开发

`security/firewall.py` 中的 `SecurityFirewall` 类管理 iptables 规则:

**规则格式:**

```python
rule = {
    "chain": "INPUT",        # INPUT / FORWARD / OUTPUT
    "protocol": "tcp",       # tcp / udp / any
    "src": "192.168.1.0/24", # 源地址
    "dst": "",               # 目的地址
    "sport": "",             # 源端口
    "dport": "443",          # 目的端口
    "action": "ACCEPT",      # ACCEPT / DROP / REJECT / LOG
    "comment": "Allow HTTPS" # 注释
}
```

**iptables 集成:**

```python
# 应用规则到 iptables
firewall._apply_to_iptables(rule)
# 生成: iptables -A INPUT -p tcp --dport 443 -m comment --comment "GK: Allow HTTPS" -j ACCEPT

# 从 iptables 移除规则
firewall._remove_from_iptables(rule)
```

### 6.5 VPN 服务开发

`security/vpn_service.py` 支持 3 种 VPN 类型:

| VPN 类型 | 说明 |
|---------|------|
| `wireguard` | WireGuard VPN |
| `ipsec` | IPSec VPN |
| `openvpn` | OpenVPN VPN |

**数据模型:**

- `VPNConfig`: VPN 服务器配置 (名称、类型、IP、端口、客户端范围等)
- `VPNClient`: VPN 客户端信息 (公钥、分配 IP、连接状态、流量统计)

**VPN 服务管理:**

```python
from security.vpn_service import VPNService

vpn = VPNService()

# 创建 VPN 配置
vpn.create_config(
    name="office-vpn",
    vpn_type="wireguard",
    server_ip="10.0.0.1",
    server_port=51820,
    client_ip_range="10.10.0.0/24"
)

# 管理客户端
vpn.add_client(config_id=1, username="user1")
vpn.remove_client(client_id=1)
vpn.get_client_status(config_id=1)
```

---

## 七、AI 引擎开发

### 7.1 模块概览

`ai_engine/` 目录包含 14 个 AI 模块:

| 模块文件 | 主要类 | 说明 |
|---------|-------|------|
| `model_manager.py` | `ModelManager` | 模型管理器 (加载/保存/版本控制) |
| `anomaly_detector.py` | `AnomalyDetector` | 异常检测器 (IsolationForest) |
| `traffic_analyzer.py` | `TrafficAnalyzer` | 流量分析器 |
| `traffic_predictor.py` | `TrafficPredictor` | 流量预测 |
| `behavior_analyzer.py` | `BehaviorAnalyzer` | 行为分析 (UEBA) |
| `threat_intelligence.py` | `ThreatIntelligenceManager` | 威胁情报管理 |
| `attack_chain.py` | `AttackChainAnalyzer` | 攻击链分析 |
| `risk_assessment.py` | `RiskAssessor` | 风险评估 |
| `llm_provider.py` | `LLMProviderConfig`, `LLMProvider` | LLM 多提供商接口 |
| `vuln_scanner.py` | `VulnerabilityScanner` | AI 漏洞扫描 |
| `adaptive_defense.py` | `AdaptiveDefense` | 自适应防御 |
| `intelligent_response.py` | `IntelligentResponse` | 智能响应 |
| `ids_optimizer.py` | `IDSOptimizer` | IDS 规则优化 |
| `ai_config.py` | - | AI 配置管理 |

### 7.2 模型管理

`ai_engine/model_manager.py` 中的 `ModelManager` 负责模型的持久化存储、加载和版本管理:

**管理的模型:**

| 模型文件 | 说明 | 算法 |
|---------|------|------|
| `isolation_forest.pkl` | 异常检测模型 | IsolationForest |
| `scaler.pkl` | 特征标准化器 | StandardScaler |
| `kmeans.pkl` | 聚类模型 | KMeans |
| `metadata.json` | 模型元数据 | JSON |

**模型生命周期:**

```python
from ai_engine.model_manager import ModelManager

manager = ModelManager()

# 加载所有模型
results = manager.load_models()
# 返回: {"isolation_forest": True, "scaler": True, "kmeans": False}

# 保存所有模型
manager.save_models()

# 加载单个模型
model = manager._load_model("isolation_forest", IsolationForest)

# 保存单个模型
manager._save_model("isolation_forest", model)
```

**安全说明:**

> 模型序列化优先使用 `joblib` (更安全、更高效)，仅在 joblib 不可用时回退到 `pickle`。请勿加载来自不可信来源的模型文件。

### 7.3 LLM 集成

`ai_engine/llm_provider.py` 提供统一的多 LLM 提供商接口:

**提供商配置数据类:**

```python
@dataclass
class LLMProviderConfig:
    name: str = ""              # 提供商名称
    provider_type: str = ""     # 提供商类型标识
    api_key: str = ""           # API Key
    api_base: str = ""          # API Base URL
    model: str = ""             # 默认模型
    max_tokens: int = 4096      # 最大 token
    temperature: float = 0.7    # 温度
    enabled: bool = False       # 是否启用
    is_default: bool = False    # 是否为默认提供商
```

**预定义提供商模板:**

- `qwen` - 通义千问
- `deepseek` - DeepSeek
- `zhipu` - 智谱 AI
- `yi` - 零一万物
- `moonshot` - Moonshot AI
- `openai` - OpenAI (兼容接口)

**API Key 加密:**

使用 `utils/crypto.py` 中的 `encrypt_data` / `decrypt_data` 对 API Key 进行加密存储。

### 7.4 异常检测

`ai_engine/anomaly_detector.py` 使用 IsolationForest 算法进行异常检测:

```python
from ai_engine.anomaly_detector import AnomalyDetector

detector = AnomalyDetector()

# 运行检测
results = detector.run_detection()
# 返回异常流量列表，包含分数和标签

# 分析单个流量特征
is_anomaly, score = detector.detect(features)
```

**检测参数:**

- 异常阈值: `GK_AI_ANOMALY_THRESHOLD` (默认 0.85)
- 分析窗口: `GK_AI_ANALYSIS_WINDOW` (默认 60 秒)
- 特征维度: `GK_AI_FEATURE_DIMENSIONS` (默认 32)

### 7.5 添加新 AI 模块指南

**步骤 1 - 创建模块文件:**

```python
# ai_engine/my_ai_module.py
"""AI 模块说明"""
from config.logging_config import get_logger
from config.settings import settings

logger = get_logger("my_ai_module")

class MyAIEngine:
    """自定义 AI 引擎"""

    def __init__(self):
        self._threshold = settings.ai_model.anomaly_threshold
        logger.info("AI 模块初始化完成")

    def analyze(self, data):
        """分析数据"""
        # 实现分析逻辑
        return {"result": "ok", "score": 0.0}
```

**步骤 2 - 在调度器中注册 (可选):**

在 `core/scheduler.py` 中添加定时任务:

```python
def _my_ai_task():
    """自定义 AI 定时任务"""
    from ai_engine.my_ai_module import MyAIEngine
    engine = MyAIEngine()
    engine.analyze(None)
```

**步骤 3 - 在初始化流程中集成 (可选):**

在 `core/app.py` 的 `initialize()` 方法中添加初始化步骤。

---

## 八、网络模块开发

### 8.1 模块概览

`network/` 目录包含 13 个网络模块:

| 模块文件 | 主要类 | 说明 |
|---------|-------|------|
| `packet_capture.py` | `PacketCapture` | 数据包捕获 (scapy) |
| `firewall.py` | `FirewallManager` | 防火墙管理 (iptables) |
| `gateway.py` | `GatewayManager` | 网关管理 (NAT/DHCP/WAN/VLAN) |
| `dhcp.py` | `DHCPService` | DHCP 服务 |
| `dns_filter.py` | `DNSFilter` | DNS 过滤 |
| `dual_wan.py` | `DualWANManager` | 双 WAN 负载均衡 |
| `dynamic_routing.py` | `DynamicRoutingManager` | 动态路由 (OSPF/BGP/FRR) |
| `bridge.py` | `BridgeManager` | 网桥管理 |
| `network_config.py` | `NetworkConfigManager` | 网络配置管理 |
| `port_scanner.py` | `PortScanner` | 端口扫描 |
| `protocol_parser.py` | `ProtocolParser` | 协议解析 |
| `speedtest.py` | `SpeedTest` | 网络测速 |

### 8.2 数据包捕获

`network/packet_capture.py` 基于 scapy 实现数据包捕获:

```python
from network.packet_capture import PacketCapture

capture = PacketCapture()

# 注册回调函数
def my_callback(packet):
    print("捕获到数据包:", packet)

capture.register_callback(my_callback)

# 启动捕获
capture.start_capture(
    interface="eth0",
    bpf_filter="tcp port 80"
)

# 停止捕获
capture.stop_capture()
```

**回调注册机制:**

```python
class PacketCapture:
    def __init__(self):
        self._callbacks: List[Callable] = []

    def register_callback(self, callback: Callable):
        """注册数据包处理回调"""
        self._callbacks.append(callback)

    def _notify_callbacks(self, packet):
        """通知所有回调"""
        for callback in self._callbacks:
            try:
                callback(packet)
            except Exception as e:
                logger.error("回调执行失败: {}".format(e))
```

**配置参数:**

- 监听接口: `GK_NET_INTERFACE` (默认 eth0)
- BPF 过滤: `GK_NET_BPF_FILTER`
- 缓冲区大小: `GK_NET_BUFFER_SIZE` (默认 256MB)
- 混杂模式: `GK_NET_PROMISCUOUS` (默认 true)

### 8.3 网关管理

`network/gateway.py` 实现完整的网关功能:

**NAT 类型:**

```python
class NATType(str, Enum):
    MASQUERADE = "masquerade"  # 动态 NAT (拨号上网)
    SNAT = "snat"              # 静态源 NAT
    DNAT = "dnat"              # 目的 NAT (端口转发)
```

**WAN 连接方式:**

```python
class WANMode(str, Enum):
    DHCP = "dhcp"      # DHCP 自动获取
    PPPOE = "pppoe"    # PPPoE 拨号
    STATIC = "static"  # 静态 IP
```

**网关功能:**

- NAT 转发 (MASQUERADE/SNAT/DNAT)
- DHCP 服务器 (多子网/VLAN 支持)
- WAN 连接管理 (DHCP/PPPoE/Static)
- VLAN 管理
- DNS 转发

### 8.4 动态路由

`network/dynamic_routing.py` 集成 FRRouting (FRR) 实现动态路由:

**支持的路由协议:**

```python
class RoutingProtocol(Enum):
    OSPF = "ospf"
    OSPF6 = "ospf6"
    BGP = "bgp"
    RIP = "rip"
    RIPNG = "ripng"
    ISIS = "isis"
```

**OSPF 配置:**

```python
@dataclass
class OSPFConfig:
    router_id: str           # 路由器 ID (如 1.1.1.1)
    areas: List[dict]        # 区域配置
    redistribute: List[str]  # 重分发 (connected/static/bgp)
    passive_interfaces: List[str]  # 被动接口
    enabled: bool = True
```

**BGP 邻居配置:**

```python
@dataclass
class BGPNeighbor:
    ip: str
    remote_as: int
    description: str = ""
    enabled: bool = True
```

**FRR 集成方式:**

通过 `vtysh` 命令行接口管理 FRR 守护进程，使用 `subprocess` 执行命令。

---

## 九、CLI 开发

### 9.1 Junos 风格 CLI

`cli/junos_cli.py` 基于 Python `cmd.Cmd` 实现 Junos 风格命令行界面:

**两种模式:**

- **操作模式 (`>`)**: 查看状态、执行操作
- **配置模式 (`#`)**: 修改系统配置

**配置文件:**

| 文件 | 说明 |
|------|------|
| `/etc/gatekeeper/junos_config.json` | 运行配置 |
| `/etc/gatekeeper/junos_candidate.json` | 候选配置 |
| `/etc/gatekeeper/junos_rollback/` | 回滚配置目录 |
| `~/.gatekeeper_junos_history` | 命令历史 |

**主要命令:**

| 模式 | 命令 | 说明 |
|------|------|------|
| 操作 | `show` | 显示系统信息 |
| 操作 | `show interfaces` | 显示网络接口 |
| 操作 | `show firewall` | 显示防火墙规则 |
| 操作 | `show alerts` | 显示告警 |
| 操作 | `ping <host>` | Ping 测试 |
| 操作 | `traceroute <host>` | 路由追踪 |
| 操作 | `configure` | 进入配置模式 |
| 配置 | `set` | 设置配置项 |
| 配置 | `delete` | 删除配置项 |
| 配置 | `show` | 查看候选配置 |
| 配置 | `commit` | 应用候选配置 |
| 配置 | `rollback` | 回退到上一版本 |
| 两种 | `exit` | 退出 |
| 两种 | `help` | 帮助 |

### 9.2 命令注册

`cli/commands.py` 中的 `CommandHandler` 类管理命令注册和执行:

```python
class CommandHandler:
    def __init__(self):
        self._commands = {
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "status": self._cmd_status,
            "version": self._cmd_version,
            "network": self._cmd_network,
            "interfaces": self._cmd_interfaces,
            "capture": self._cmd_capture,
            "scan": self._cmd_scan,
            "portscan": self._cmd_portscan,
            "firewall": self._cmd_firewall,
            "alerts": self._cmd_alerts,
            # ... 更多命令
        }

    def execute(self, command: str, args: list):
        """执行命令"""
        handler = self._commands.get(command)
        if handler:
            return handler(args)
        return "未知命令: {}".format(command)
```

### 9.3 添加新命令指南

**步骤 1 - 在 CommandHandler 中添加命令方法:**

```python
# cli/commands.py
class CommandHandler:
    def __init__(self):
        # ... 已有命令 ...
        self._commands["my_command"] = self._cmd_my_command

    def _cmd_my_command(self, args):
        """自定义命令处理"""
        if not args:
            return "用法: my_command <参数>"
        # 实现命令逻辑
        return "命令执行结果"
```

**步骤 2 - (可选) 在 Junos CLI 中注册:**

在 `cli/junos_cli.py` 的操作模式和配置模式中添加对应的命令方法。

**步骤 3 - (可选) 添加命令补全:**

在 `cli/completer.py` 中添加命令补全规则。

---

## 十、前端开发

### 10.1 模板结构

项目使用 Jinja2 模板引擎，所有模板位于 `web/templates/` 目录 (共 33 个 HTML 文件)。

**基础模板 (base.html):**

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{% block title %}GateKeeper{% endblock %}</title>
    <!-- CSS 框架和自定义样式 -->
</head>
<body>
    <!-- 导航栏 -->
    <nav>
        <a href="/">仪表盘</a>
        <a href="/network">网络</a>
        <a href="/ids">IDS</a>
        <!-- ... 更多导航链接 ... -->
    </nav>

    <!-- 主内容区域 -->
    <div class="content">
        {% block content %}{% endblock %}
    </div>

    <!-- JavaScript -->
    <script src="/static/js/common.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
```

**模板继承:**

```html
{% extends "base.html" %}

{% block title %}我的模块 - GateKeeper{% endblock %}

{% block content %}
<div class="container">
    <h2>模块标题</h2>
    <div id="data-container">
        <!-- 动态内容 -->
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    // 模块特定的 JavaScript
</script>
{% endblock %}
```

### 10.2 JavaScript 规范

**safeFetch 模式 (API 调用):**

```javascript
async function safeFetch(url, options = {}) {
    try {
        var response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            ...options
        });
        var data = await response.json();
        if (data.status === 'error') {
            showToast(data.message, 'error');
            return null;
        }
        return data;
    } catch (error) {
        showToast('请求失败: ' + error.message, 'error');
        return null;
    }
}
```

**CSRF Token 获取:**

```javascript
function getCsrfToken() {
    var metas = document.getElementsByTagName('meta');
    for (var i = 0; i < metas.length; i++) {
        if (metas[i].getAttribute('name') === 'csrf-token') {
            return metas[i].getAttribute('content');
        }
    }
    return null;
}
```

**SSE 事件处理:**

```javascript
var eventSource = new EventSource('/events');
eventSource.addEventListener('alert', function(event) {
    var data = JSON.parse(event.data);
    updateAlertBadge(data.count);
});
eventSource.onerror = function() {
    setTimeout(function() { location.reload(); }, 5000);
};
```

**表单验证:**

```javascript
function validateForm(formElement) {
    var inputs = formElement.querySelectorAll('[required]');
    for (var i = 0; i < inputs.length; i++) {
        if (!inputs[i].value.trim()) {
            showToast(inputs[i].getAttribute('data-error') || '请填写必填项', 'error');
            inputs[i].focus();
            return false;
        }
    }
    return true;
}
```

### 10.3 添加新页面指南

**步骤 1 - 创建模板文件:**

```html
<!-- web/templates/my_module.html -->
{% extends "base.html" %}
{% block title %}我的模块{% endblock %}
{% block content %}
<div class="container-fluid">
    <div class="page-header">
        <h2>我的模块</h2>
    </div>
    <div class="row">
        <div class="col-md-12">
            <div class="card">
                <div class="card-body">
                    <div id="module-content">
                        <!-- 内容区域 -->
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
{% block scripts %}
<script src="/static/js/my_module.js"></script>
{% endblock %}
```

**步骤 2 - 创建路由 (参考 5.9 节)**

**步骤 3 - 添加导航链接 (参考 5.9 节)**

**步骤 4 - 创建静态资源 (可选):**

```
web/static/js/my_module.js
web/static/css/my_module.css
```

---

## 十一、测试

### 11.1 测试框架

- **测试框架**: pytest >= 8.0.0
- **覆盖率**: pytest-cov >= 4.1.0
- **配置文件**: `pytest.ini`, `conftest.py`
- **Mock**: unittest.mock

### 11.2 测试文件

| 文件 | 说明 |
|------|------|
| `tests/conftest.py` | 测试配置和公共 fixtures |
| `tests/test_web_routes.py` | Web 路由测试 |
| `tests/test_ai_engine.py` | AI 引擎测试 |
| `tests/test_alerting.py` | 告警系统测试 |
| `tests/test_cli.py` | CLI 测试 |
| `tests/test_network.py` | 网络模块测试 |
| `tests/test_network_modules.py` | 网络模块详细测试 |
| `tests/test_security_modules.py` | 安全模块测试 |

### 11.3 运行测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行特定测试文件
pytest tests/test_web_routes.py -v
pytest tests/test_ai_engine.py -v
pytest tests/test_security_modules.py -v

# 运行特定测试用例
pytest tests/test_web_routes.py::TestAuth::test_login -v

# 带覆盖率报告
pytest tests/ --cov=. --cov-report=html --cov-report=term

# 仅运行失败的测试
pytest tests/ --lf

# 并行运行 (需要 pytest-xdist)
pytest tests/ -n auto
```

### 11.4 编写测试指南

**公共 Fixtures (tests/conftest.py):**

```python
# 数据库 fixtures
@pytest.fixture(scope="session")
def db_engine():
    """内存 SQLite 引擎 (session 级别)"""

@pytest.fixture(scope="function")
def db_session(db_tables):
    """函数级别数据库会话 (自动清理)"""

@pytest.fixture(scope="function")
def db_manager_mock(db_session):
    """Mock DatabaseManager"""

# Flask fixtures
@pytest.fixture(scope="function")
def app(db_manager_mock):
    """Flask 测试应用"""

@pytest.fixture(scope="function")
def client(app):
    """Flask 测试客户端"""

# 用户 fixtures
@pytest.fixture(scope="function")
def test_users(db_session):
    """创建测试用户 (super_admin/admin/operator/viewer)"""

@pytest.fixture(scope="function")
def authenticated_client(client, test_users):
    """已认证的测试客户端"""
```

**单元测试示例:**

```python
def test_alert_creation(db_session):
    """测试告警创建"""
    from core.models import Alert, AlertLevel, AlertStatus

    alert = Alert(
        title="测试告警",
        level=AlertLevel.HIGH,
        status=AlertStatus.NEW,
        source="test"
    )
    db_session.add(alert)
    db_session.flush()

    assert alert.id is not None
    assert alert.level == AlertLevel.HIGH
```

**集成测试示例:**

```python
def test_login_success(client, test_users):
    """测试登录成功"""
    response = client.post('/auth/login', json={
        "username": "test_admin",
        "password": "Ad@Test2026!"
    })
    data = response.get_json()
    assert data["status"] == "ok"
    assert "data" in data
```

**安全引擎测试示例:**

```python
def test_ids_detection(ids_engine):
    """测试 IDS 攻击检测"""
    result = ids_engine.check_signature("SELECT * FROM users WHERE 1=1 UNION SELECT * FROM passwords")
    assert result is not None
    assert result.attack_type == AttackType.SQL_INJECTION
```

---

## 十二、编码规范

### 12.1 Python 规范

- **风格**: 遵循 PEP 8
- **格式化**: black (target Python 3.7)
- **Linting**: flake8
- **类型注解**: 推荐使用 Type Hints
- **导入**: 绝对导入优先，避免循环导入

**配置文件:**

- `.flake8` - flake8 配置
- `.coveragerc` - 测试覆盖率配置
- `.pre-commit-config.yaml` - pre-commit 钩子

### 12.2 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 文件名 | snake_case | `ids_engine.py`, `packet_capture.py` |
| 类名 | PascalCase | `IDSEngine`, `PacketCapture`, `ModelManager` |
| 函数/方法 | snake_case | `get_session()`, `load_models()` |
| 变量 | snake_case | `db_manager`, `is_enabled` |
| 常量 | UPPER_SNAKE_CASE | `MAX_LOGIN_ATTEMPTS`, `DEFAULT_PORT` |
| 蓝图变量 | xxx_bp | `auth_bp`, `dashboard_bp` |
| API 路由函数 | api_xxx | `api_get_data()`, `api_create_rule()` |
| 页面路由函数 | xxx | `index()`, `login()` |
| 私有方法 | _xxx | `_create_default_admin()`, `_lazy_import()` |
| 环境变量 | UPPER_SNAKE_CASE (GK_ 前缀) | `GK_WEB_PORT`, `GK_DB_DRIVER` |

### 12.3 文档规范

- 所有公共函数和类必须有 docstring
- 模块级别 docstring 描述模块用途
- 使用三引号 docstring (`"""..."""`)
- 注释使用英文 (面向开发者的输出文本使用英文)
- 复杂逻辑添加行内注释

```python
def analyze_traffic(self, packet_data):
    """分析网络流量数据，检测异常行为。

    Args:
        packet_data: 原始数据包数据

    Returns:
        dict: 包含分析结果的字典
            - is_anomaly (bool): 是否异常
            - score (float): 异常分数 (0.0-1.0)
            - threat_type (str): 威胁类型

    Raises:
        ValueError: 当 packet_data 格式无效时
    """
```

### 12.4 Git 规范

**分支命名:**

| 类型 | 格式 | 示例 |
|------|------|------|
| 功能分支 | `feature/xxx` | `feature/dns-filter` |
| 修复分支 | `bugfix/xxx` | `bugfix/login-redirect` |
| 热修复 | `hotfix/xxx` | `hotfix/csrf-bypass` |
| 发布分支 | `release/vX.X.X` | `release/v1.1.0` |

**Commit 消息格式:**

```
type(scope): description

# type: feat, fix, docs, style, refactor, test, chore
# scope: 模块名 (如 auth, ids, web, ai)
# description: 简短描述 (英文)
```

示例:
```
feat(ids): add port scan detection signature
fix(auth): resolve session expiry on password change
docs(api): update Swagger annotations for alert endpoints
```

### 12.5 安全编码规范

**密码处理:**

```python
from utils.crypto import hash_password, verify_password

# 哈希密码
password_hash = hash_password("MyP@ssw0rd!")

# 验证密码
is_valid = verify_password("input_password", stored_hash)
```

**SQL 安全:**

- 始终使用 SQLAlchemy ORM，禁止拼接原始 SQL
- 如需原始查询，使用参数化查询:

```python
# 安全: 使用参数化查询
result = session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})

# 危险: 禁止字符串拼接
# result = session.execute(text("SELECT * FROM users WHERE id = {}".format(user_id)))
```

**CSRF 保护:**

- 所有 POST 路由必须处理 CSRF
- 如需豁免，使用 `csrf.exempt()` 并说明原因
- 前端 AJAX 请求必须携带 `X-CSRFToken` header

**敏感数据保护:**

- 日志中使用 `SensitiveDataFilter` 自动过滤敏感信息
- 配置导出时自动脱敏 (`password` -> `***`)
- API Key 使用 `utils/crypto.py` 加密存储

**输入验证:**

```python
# 始终验证和清理用户输入
data = request.json if request.is_json else {}
username = data.get("username", "").strip()
if not username or len(username) > 64:
    return jsonify({"status": "error", "message": "无效的用户名"}), 400
```

---

## 十三、调试与排障

### 13.1 日志系统

**日志管理器 (config/logging_config.py):**

`LogManager` 是统一的日志管理入口，提供以下功能:

- **根日志**: 输出到控制台和文件，支持 RotatingFileHandler
- **安全审计日志**: 独立的审计日志文件，按天轮转，保留 90 天
- **JSON 格式**: 通过 `GK_LOG_FORMAT=json` 启用结构化日志
- **颜色输出**: 控制台日志支持 ANSI 颜色
- **敏感数据过滤**: `SensitiveDataFilter` 自动过滤 password/secret/token/api_key

**日志文件:**

| 文件 | 说明 |
|------|------|
| `logs/gatekeeper.log` | 主日志文件 (RotatingFileHandler, 100MB x 10) |
| `logs/security_audit.log` | 安全审计日志 (TimedRotatingFileHandler, 按天轮转, 保留 90 天) |

**安全审计事件记录:**

```python
from config.logging_config import log_security_event

log_security_event(
    user="admin",
    action="firewall_add",
    resource="192.168.1.100:443",
    result="success",
    message="添加防火墙规则: 允许 HTTPS"
)
```

**审计日志格式:**

```
2026-05-14 10:30:00 | AUDIT | INFO     | admin | firewall_add | 192.168.1.100:443 | success | 添加防火墙规则
```

### 13.2 常见问题

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| `DetachedInstanceError` | 在 session 关闭后访问 ORM 对象属性 | 在 session 关闭前调用 `session.expunge(obj)` |
| CSRF 400 错误 | POST 请求缺少 CSRF token | 前端添加 `X-CSRFToken` header，或对路由使用 `csrf.exempt()` |
| `UserRole` 枚举不匹配 | 数据库中存储小写值，枚举使用大写 | 使用 `role.value` 比较，或确保数据库存储大写值 |
| SQLite locked | 多线程并发写入 SQLite | 使用 `StaticPool` (已默认配置) |
| 端口已被占用 | 8443 端口被其他进程占用 | 修改 `GK_WEB_PORT` 或 `kill` 占用进程 |
| SECRET_KEY 警告 | 未配置 `GK_WEB_SECRET_KEY` | 设置环境变量，系统会自动生成并持久化 |
| 模块导入失败 | 依赖未安装或路径错误 | 运行 `pip install -r requirements.txt` |
| Web 服务启动超时 | SSL 证书生成失败或端口冲突 | 检查日志，确认端口可用 |

### 13.3 调试模式

**启用调试模式:**

```bash
# Flask 调试模式
export GK_WEB_DEBUG=true

# 详细日志
export GK_LOG_LEVEL=DEBUG
export GK_LOG_CONSOLE=true

# SQL 日志
export GK_DB_ECHO=true

# JSON 结构化日志
export GK_LOG_FORMAT=json
```

**pytest 调试:**

```bash
# 显示 print 输出
pytest tests/ -s

# 进入调试器 (失败时)
pytest tests/ --pdb

# 显示最慢的 10 个测试
pytest tests/ --durations=10
```

---

## 十四、部署指南

### 14.1 ISO 部署

**ISO 构建流程:**

1. 准备 Debian 10 基础 ISO
2. 修改 `iso_build/preseed.cfg` 配置自动安装参数
3. 打包 GateKeeper 项目到 `gatekeeper.tar.gz`
4. 运行 `build_iso_debian10.sh` 或 `build_iso_pycdlib.py` 生成 ISO

**preseed.cfg 关键配置:**

- 自动分区 (使用整个磁盘)
- 创建 `admin` 用户
- 安装最小化系统 + SSH 服务器
- 执行 `late-command.sh` (安装后脚本)

**首次启动流程 (scripts/first-start.sh):**

1. 设置目录权限 (`/opt/gatekeeper/`)
2. 配置 SSH (PasswordAuthentication, MaxAuthTries=3)
3. 配置 Junos CLI 为默认 shell
4. 创建 Python 虚拟环境
5. 安装 pip 依赖
6. 初始化数据库
7. 生成 SSL 自签名证书
8. 配置 systemd 服务
9. 配置 iptables 防火墙规则
10. 安装配置 fail2ban
11. 清理安装标记

### 14.2 systemd 服务

**服务管理脚本 (scripts/run-service.sh):**

```bash
# 启动服务
sudo /opt/gatekeeper/scripts/run-service.sh start

# 停止服务
sudo /opt/gatekeeper/scripts/run-service.sh stop

# 重启服务
sudo /opt/gatekeeper/scripts/run-service.sh restart

# 查看状态
sudo /opt/gatekeeper/scripts/run-service.sh status
```

**systemctl 命令:**

```bash
# 管理主服务
sudo systemctl start gatekeeper
sudo systemctl stop gatekeeper
sudo systemctl restart gatekeeper
sudo systemctl status gatekeeper

# 查看日志
sudo journalctl -u gatekeeper -f
```

### 14.3 SSL 证书

**自动生成 (默认行为):**

系统首次启动时，如果 SSL 证书不存在，会自动生成自签名证书 (有效期 10 年)，保存到 `data/certs/server.crt` 和 `data/certs/server.key`。

**Let's Encrypt 证书:**

```bash
# 获取证书
sudo /opt/gatekeeper/scripts/cert-manager.sh obtain

# 安装自动续签
sudo /opt/gatekeeper/scripts/cert-manager.sh cron-install

# 查看帮助
sudo /opt/gatekeeper/scripts/cert-manager.sh help
```

**自定义证书:**

将证书文件放置到配置指定的路径:

```bash
export GK_WEB_SSL_CERT=/path/to/server.crt
export GK_WEB_SSL_KEY=/path/to/server.key
```

### 14.4 备份与恢复

**备份脚本 (scripts/backup.sh):**

```bash
# 执行备份
sudo /opt/gatekeeper/scripts/backup.sh

# 备份内容:
# - 数据库文件 (data/gatekeeper.db)
# - 配置文件 (data/*.json)
# - SSL 证书 (data/certs/)
# - AI 模型 (models/)
# - 日志文件 (logs/)
```

**手动备份:**

```bash
# 打包备份
tar czf gatekeeper-backup-$(date +%Y%m%d).tar.gz \
    /opt/gatekeeper/data/ \
    /opt/gatekeeper/models/ \
    /opt/gatekeeper/config/
```

### 14.5 安全加固

**iptables 防火墙 (first-start.sh):**

```bash
# 默认规则
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 允许 SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# 允许 Web
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# 允许 HTTP 重定向
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# 允许回环
iptables -A INPUT -i lo -j ACCEPT

# 允许已建立连接
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

**fail2ban 配置:**

```bash
# 安装 fail2ban
sudo apt-get install -y fail2ban

# 配置 GateKeeper jail
# [gatekeeper]
# enabled = true
# port = 8443
# filter = gatekeeper
# logpath = /opt/gatekeeper/logs/gatekeeper.log
# maxretry = 5
# bantime = 3600
```

**SSH 加固:**

```bash
# 限制认证尝试次数
MaxAuthTries 3

# 缩短登录超时
LoginGraceTime 30

# 禁用 root 密码登录 (生产环境)
# PermitRootLogin prohibit-password
```

---

## 附录

### A. 依赖清单

核心依赖 (requirements.txt):

| 包名 | 版本要求 | 说明 |
|------|---------|------|
| `flask` | >=2.0.0,<3.0.0 | Web 框架 |
| `flask-login` | >=0.5.0 | 用户认证 |
| `flask-wtf` | >=1.0.0 | CSRF 保护 |
| `flask-limiter` | >=3.5.0 | 速率限制 |
| `werkzeug` | >=2.0.0 | WSGI 工具 |
| `markupsafe` | >=2.0.0 | HTML 转义 |
| `sqlalchemy` | >=1.4.0,<2.0.0 | ORM |
| `alembic` | >=1.7.0 | 数据库迁移 |
| `scapy` | >=2.4.5 | 数据包捕获 |
| `dpkt` | >=1.9.0 | 协议解析 |
| `scikit-learn` | >=0.24.0 | 机器学习 |
| `numpy` | >=1.20.0,<2.0.0 | 数值计算 |
| `pandas` | >=1.3.0 | 数据分析 |
| `joblib` | >=1.0.0 | 模型序列化 |
| `schedule` | >=1.1.0 | 任务调度 |
| `apscheduler` | >=3.8.0 | 高级调度器 |
| `paramiko` | >=2.10.0 | SSH 客户端 |
| `reportlab` | >=3.6.0 | PDF 生成 |
| `email-validator` | >=2.0.0 | 邮箱验证 |
| `prompt-toolkit` | >=3.0.0 | CLI 交互 |
| `psutil` | >=5.8.0 | 系统信息 |
| `cryptography` | >=3.4.0 | 加密库 |
| `requests` | >=2.25.0 | HTTP 客户端 |
| `ldap3` | >=2.9.0 | LDAP/AD 集成 |
| `flasgger` | >=0.9.7.1 | Swagger 文档 |

开发依赖 (extras_require="dev"):

| 包名 | 版本要求 | 说明 |
|------|---------|------|
| `pytest` | >=8.0.0 | 测试框架 |
| `pytest-cov` | >=4.1.0 | 测试覆盖率 |
| `black` | >=24.0.0 | 代码格式化 |
| `flake8` | >=7.0.0 | 代码检查 |
| `mypy` | >=1.8.0 | 类型检查 |

### B. 默认端口

| 端口 | 服务 | 说明 |
|------|------|------|
| `8443` | Web 管理面板 | HTTPS (默认) |
| `8080` | Web 管理面板 | HTTP (Docker/降级模式) |
| `22` | SSH | 系统远程管理 |
| `51820` | WireGuard | VPN 服务 |
| `500` | UDP | IPSec |
| `1194` | OpenVPN | VPN 服务 |

### C. 默认账户

| 用户名 | 角色 | 说明 |
|--------|------|------|
| `admin-sp` | SUPER_ADMIN | 超级管理员，可管理所有模块和用户 |
| `admin` | ADMIN | 管理员，可管理用户和配置 |
| `root` | (系统) | 操作系统 root 用户 (SSH) |

> 首次启动时自动创建，密码通过环境变量设置或随机生成。随机密码写入 `/opt/gatekeeper/.initial_credentials` 文件 (权限 600)。

### D. API 端点速查表

#### 认证

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/auth/login` | 用户登录 |
| POST | `/auth/logout` | 用户登出 |
| POST | `/auth/verify_2fa` | 2FA 验证 |
| GET | `/auth/status` | 认证状态 |

#### 仪表盘

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/` | 仪表盘页面 |
| GET | `/api/dashboard/stats` | 仪表盘统计数据 |
| GET | `/api/dashboard/alerts` | 最新告警 |

#### 网络管理

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/network` | 网络管理页面 |
| GET | `/api/network/interfaces` | 获取网络接口列表 |
| GET | `/api/network/traffic` | 获取流量数据 |
| POST | `/api/network/interfaces/refresh` | 刷新接口状态 |

#### 防火墙

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/firewall/rules` | 获取防火墙规则 |
| POST | `/api/firewall/rules` | 添加防火墙规则 |
| PUT | `/api/firewall/rules/<id>` | 更新规则 |
| DELETE | `/api/firewall/rules/<id>` | 删除规则 |
| POST | `/api/firewall/rules/<id>/toggle` | 启用/禁用规则 |

#### IDS

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/ids` | IDS 管理页面 |
| GET | `/api/ids/alerts` | 获取 IDS 告警 |
| GET | `/api/ids/rules` | 获取 IDS 规则 |
| POST | `/api/ids/rules` | 添加 IDS 规则 |
| GET | `/api/ids/banned-ips` | 获取封禁 IP 列表 |
| POST | `/api/ids/unban/<ip>` | 解封 IP |

#### 告警

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/alerts` | 告警管理页面 |
| GET | `/api/alerts` | 获取告警列表 |
| PUT | `/api/alerts/<id>/acknowledge` | 确认告警 |
| PUT | `/api/alerts/<id>/resolve` | 解决告警 |

#### VPN

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/vpn` | VPN 管理页面 |
| GET | `/api/vpn/configs` | 获取 VPN 配置 |
| POST | `/api/vpn/configs` | 创建 VPN 配置 |
| GET | `/api/vpn/clients` | 获取 VPN 客户端 |

#### 系统设置

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/settings` | 设置页面 |
| GET | `/api/settings` | 获取系统配置 |
| PUT | `/api/settings` | 更新系统配置 |
| POST | `/api/change-password` | 修改密码 |

#### 健康检查

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查端点 |

#### SSE

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/events` | Server-Sent Events 实时推送 |

### E. 常用命令速查

**CLI 命令:**

```bash
# 启动主服务
python3 -m core.app --web

# Junos 风格 CLI
python3 cli/junos_cli.py
# 或安装后
gk-junos

# Cisco 风格 CLI
python3 cli/cisco_cli.py
# 或安装后
gk-cisco

# 通用 CLI
python3 cli/main.py
# 或安装后
gk-cli
```

**systemctl 命令:**

```bash
sudo systemctl start gatekeeper    # 启动
sudo systemctl stop gatekeeper     # 停止
sudo systemctl restart gatekeeper  # 重启
sudo systemctl status gatekeeper   # 状态
sudo systemctl enable gatekeeper   # 开机自启
```

**journalctl 命令:**

```bash
sudo journalctl -u gatekeeper -f           # 实时日志
sudo journalctl -u gatekeeper --since today # 今日日志
sudo journalctl -u gatekeeper -n 100        # 最近 100 行
```

**运维脚本:**

```bash
/opt/gatekeeper/scripts/start.sh            # 启动
/opt/gatekeeper/scripts/stop.sh             # 停止
/opt/gatekeeper/scripts/backup.sh           # 备份
```
