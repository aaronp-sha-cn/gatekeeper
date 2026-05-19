# GateKeeper - AI安全网络防御系统

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Debian 10](https://img.shields.io/badge/OS-Debian%2010%20Buster-red.svg)](https://www.debian.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 概述

GateKeeper 是一个基于 Python 的 AI 安全网络防御系统，专为 Debian 10 (Buster) 设计。它集成了流量分析、异常检测、漏洞扫描、自适应防御和威胁情报等核心功能，为网络安全提供全方位的保护。系统提供 ISO 一键安装，支持 BIOS 和 UEFI 双启动模式。

## 核心功能

- **AI 流量分析** - 基于机器学习的实时网络流量分析与异常检测
- **入侵检测系统 (IDS)** - 智能化的入侵检测与规则优化
- **漏洞扫描** - 自动化网络漏洞发现与评估
- **自适应防御** - 基于威胁情报的动态防御策略调整
- **防火墙管理** - 集成的防火墙规则管理与自动化
- **WAF 防火墙** - Web 应用防火墙，内置 201 条防护规则
- **网关防病毒** - 网关级病毒扫描（支持 ClamAV）
- **威胁情报** - 实时威胁情报收集与分析
- **告警系统** - 多渠道告警通知（邮件、Webhook）
- **Web 管理面板** - 可视化的安全管理界面（HTTPS）
- **CLI 工具** - 功能完善的命令行管理工具
- **双因素认证 (2FA)** - TOTP 双因素认证，支持备用恢复码
- **LDAP/AD 集成** - 企业级身份认证集成
- **SSL/TLS 解密** - SSL 中间人检测（可选）
- **沙箱分析** - 文件沙箱行为分析（可选）
- **VPN 管理** - VPN 隧道管理
- **QoS 流量控制** - 网络流量优先级管理
- **内容安全** - URL 过滤和内容审计
- **零信任网络** - 微隔离和零信任架构（可选）
- **高可用 (HA)** - 主备切换和集群支持（可选）

## 系统要求

- **操作系统**: Debian 10 (Buster)
- **Python**: 3.7+（系统自带）
- **内存**: 4GB+（推荐 8GB）
- **磁盘**: 20GB+
- **网络**: 至少一个网络接口
- **权限**: root（用于网络抓包和防火墙管理）

## ISO 安装部署（推荐）

### 1. 下载 ISO

从项目发布页面下载最新的 `gatekeeper-installer.iso` 文件。

### 2. 制作启动介质

**Linux/Mac:**
```bash
# 插入U盘，确认设备名
lsblk

# 写入ISO（注意替换 /dev/sdX 为实际设备名）
sudo dd if=gatekeeper-installer.iso of=/dev/sdX bs=4M status=progress && sync
```

**Windows:**
使用 [Rufus](https://rufus.ie/) 或 [balenaEtcher](https://www.balena.io/etcher/) 写入ISO。

**虚拟机:**
直接挂载 ISO 文件作为 CD-ROM 启动。

### 3. 启动安装

1. 从启动介质引导系统
2. 选择 **"GateKeeper - 自动安装 (推荐)"**
3. 系统自动完成以下操作：
   - 磁盘分区和格式化
   - Debian 10 基础系统安装
   - GateKeeper 部署和配置
   - 服务启动

⏱️ 安装时间约 10-20 分钟（取决于网络速度）。

### 4. 安装完成后

**查看初始凭据:**
```bash
cat /opt/gatekeeper/.initial_credentials
```

输出示例：
```
admin-sp:AbC123!@#xyz    # 超级管理员
admin:XYZ789#@!abc       # 管理员
root:Root456!@#pass      # 系统root
```

**访问 Web 管理面板:**
```
URL: https://<服务器IP>:8443
账号: admin-sp 或 admin
密码: 查看上方凭据文件
```

> ⚠️ 首次登录后系统会要求修改密码。

**检查服务状态:**
```bash
systemctl status gatekeeper
journalctl -u gatekeeper -f    # 实时日志
```

## 手动安装

```bash
# 克隆项目
git clone https://github.com/gatekeeper-security/GateKeeper.git
cd GateKeeper

# 运行安装脚本
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# 启动系统
sudo systemctl start gatekeeper
```

## Docker 部署

```bash
# 构建镜像
docker build -t gatekeeper:latest .

# 运行容器
docker run -d \
  --name gatekeeper \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -p 8443:8443 \
  -v gatekeeper-data:/opt/gatekeeper/data \
  -e GK_WEB_SSL_ENABLED=false \
  -e GK_DB_DRIVER=sqlite \
  gatekeeper:latest
```

## 项目结构

```
GateKeeper/
├── config/          # 配置文件（settings, database, logging）
├── core/            # 核心模块（models, app, scheduler, audit）
├── ai_engine/       # AI引擎（traffic_analyzer, anomaly_detector, model_manager）
├── network/         # 网络模块（firewall, packet_capture, gateway, dns_filter）
├── cli/             # 命令行工具
├── web/             # Web管理面板（Flask应用、路由、模板、静态资源）
├── alerting/        # 告警系统（邮件、Webhook）
├── reports/         # 报表生成
├── utils/           # 工具函数（crypto, helpers）
├── security/        # 安全模块（IDS, 2FA, compliance, sandbox）
├── tests/           # 测试套件
├── scripts/         # 运维脚本（install, first-start, backup, cert-manager）
├── docs/            # 文档（ARCHITECTURE.md）
├── iso_build/       # ISO构建（preseed, build scripts）
└── data/            # 数据目录（数据库、证书、AI模型）
```

## 使用方法

### Web 管理面板

启动后访问 `https://<服务器IP>:8443`，使用默认账号登录。

**默认账号:**
| 账号 | 角色 | 说明 |
|------|------|------|
| `admin-sp` | 超级管理员 | 可管理所有模块和用户 |
| `admin` | 管理员 | 可管理用户和配置 |

> 初始密码在安装时自动生成，请查看 `/opt/gatekeeper/.initial_credentials`。

### CLI 工具

```bash
# 进入交互式CLI
gk-cli

# 查看网络状态
gk-cli> network status

# 启动流量捕获
gk-cli> capture start eth0

# 运行漏洞扫描
gk-cli> scan 192.168.1.0/24
```

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `GK_WEB_PORT` | Web 服务端口 | `8443` |
| `GK_WEB_SSL_ENABLED` | 启用 SSL/TLS | `true` |
| `GK_WEB_SECRET_KEY` | Flask 密钥 | 自动生成 |
| `GK_DB_DRIVER` | 数据库驱动 (`sqlite`/`postgresql`) | `sqlite` |
| `GK_DB_HOST` | 数据库主机 | `localhost` |
| `GK_DB_PORT` | 数据库端口 | `5432` |
| `GK_DB_NAME` | 数据库名称 | `gatekeeper` |
| `GK_DB_USER` | 数据库用户 | `gatekeeper` |
| `GK_DB_PASSWORD` | 数据库密码 | (空) |
| `GK_ADMIN_SP_PASSWORD` | 超级管理员初始密码 | 自动生成 |
| `GK_ADMIN_PASSWORD` | 管理员初始密码 | 自动生成 |
| `GK_LOG_LEVEL` | 日志级别 | `INFO` |
| `GK_LOG_FORMAT` | 日志格式 (`text`/`json`) | `text` |
| `GK_CAPTURE_INTERFACE` | 默认抓包网卡 | `eth0` |
| `GK_AI_MODEL_PATH` | AI 模型路径 | `models/` |

## 配置

主配置文件位于 `config/settings.py`，可根据实际环境修改数据库、网络、AI模型等参数。所有配置均可通过 `GK_` 前缀的环境变量覆盖。

## 安全特性

- CSRF 保护（Flask-WTF）
- 速率限制（Flask-Limiter，可选）
- 密码哈希（bcrypt）
- 首次登录强制修改密码
- 登录失败锁定机制
- 双因素认证（TOTP）
- SSL/TLS 加密通信
- 自动生成随机 SECRET_KEY
- 安全审计日志

## 已知限制

- `mitmproxy` 需要 Python 3.8+，Debian 10 默认 Python 3.7 不支持 SSL 解密功能
- ClamAV 需要单独安装（`scripts/install-security-services.sh`）
- 部分高级功能（沙箱、零信任）需要额外配置

## 许可证

MIT License
