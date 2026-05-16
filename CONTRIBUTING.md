# GateKeeper 贡献指南

感谢你对 GateKeeper 项目的关注！本文档将帮助你快速上手开发环境并了解代码贡献流程。

## 目录

- [开发环境搭建](#开发环境搭建)
- [代码风格指南](#代码风格指南)
- [运行测试](#运行测试)
- [提交 Pull Request](#提交-pull-request)
- [分支命名规范](#分支命名规范)
- [提交信息格式](#提交信息格式)
- [项目结构概览](#项目结构概览)

## 开发环境搭建

### 前置要求

- Python 3.7+（Debian 10 系统自带 Python 3.7）
- pip
- SQLite3（开发环境默认数据库）
- Git

### 克隆项目

```bash
git clone https://github.com/your-org/gatekeeper.git
cd gatekeeper
```

### 创建虚拟环境

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# 或 venv\Scripts\activate  # Windows
```

### 安装依赖

```bash
pip install -r requirements.txt
```

### 安装开发工具

```bash
pip install flake8 black pytest pytest-cov isort
```

### 数据库初始化

```bash
python -c "from config.database import init_db; init_db()"
```

### 启动开发服务

```bash
python -m core.app --capture
```

Web 管理面板默认运行在 `https://127.0.0.1:8443`。

## 代码风格指南

GateKeeper 遵循以下代码规范：

### PEP 8 (flake8)

使用 flake8 进行静态检查：

```bash
flake8 --config=.flake8 .
```

项目根目录的 `.flake8` 文件已配置好规则，主要要求：

- 每行最大长度：120 字符
- 缩进：4 空格
- 导入顺序：标准库 -> 第三方库 -> 本地模块
- 类名使用 PascalCase
- 函数名使用 snake_case
- 常量使用 UPPER_SNAKE_CASE

### Black 代码格式化

使用 black 自动格式化代码：

```bash
black --line-length=120 --target-version=py37 .
```

### isort 导入排序

```bash
isort --profile=black --line-length=120 .
```

### 类型注解

新增代码鼓励使用 Python 类型注解：

```python
from typing import Dict, List, Optional

def analyze_traffic(
    packets: List[Dict[str, Any]],
    threshold: float = 0.85,
) -> Optional[Dict[str, Any]]:
    ...
```

### 文档字符串

所有公共模块、类、方法应使用中文文档字符串：

```python
class FirewallManager:
    """
    防火墙管理器
    管理iptables防火墙规则的增删改查
    """

    def add_rule(self, name: str, action: str = "DROP") -> Dict[str, Any]:
        """
        添加防火墙规则

        Args:
            name: 规则名称
            action: 动作 (ACCEPT/DROP/REJECT/LOG)

        Returns:
            添加结果字典
        """
```

## 运行测试

### 运行全部测试

```bash
pytest tests/ -v
```

### 运行特定模块测试

```bash
pytest tests/test_network_modules.py -v
pytest tests/test_security_modules.py -v
```

### 带覆盖率报告

```bash
pytest tests/ --cov=. --cov-report=html --cov-report=term-missing
```

覆盖率报告将生成在 `htmlcov/` 目录中。

### 运行单个测试文件

```bash
pytest tests/test_web_routes.py::TestLogin::test_login_success -v
```

## 提交 Pull Request

### PR 流程

1. **Fork** 项目到你的 GitHub 账号
2. 基于最新的 `main` 分支创建你的功能分支
3. 开发并提交你的更改
4. 确保所有测试通过：`pytest tests/ -v`
5. 运行代码检查：`flake8 . && black --check .`
6. 推送到你的 Fork 仓库
7. 创建 Pull Request

### PR 描述模板

```markdown
## 变更说明
简要描述本次变更的内容和目的。

## 变更类型
- [ ] 新功能 (feature)
- [ ] Bug 修复 (bugfix)
- [ ] 文档更新 (docs)
- [ ] 代码重构 (refactor)
- [ ] 安全修复 (security)

## 测试
- [ ] 已添加单元测试
- [ ] 所有测试通过
- [ ] 已运行 flake8 和 black 检查

## 关联 Issue
Closes #<issue_number>
```

### 代码审查

- 至少需要一位维护者审查通过
- CI 自动化检查必须全部通过
- 如有冲突需及时 rebase

## 分支命名规范

| 类型 | 前缀 | 示例 |
|------|------|------|
| 新功能 | `feature/` | `feature/ipv6-support` |
| Bug 修复 | `bugfix/` | `bugfix/login-timeout` |
| 文档 | `docs/` | `docs/api-documentation` |
| 重构 | `refactor/` | `refactor/firewall-module` |
| 安全修复 | `security/` | `security/xss-prevention` |
| 紧急修复 | `hotfix/` | `hotfix/memory-leak` |

分支名使用小写字母，单词间用连字符 `-` 分隔。

## 提交信息格式

遵循 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Type 类型

| 类型 | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档变更 |
| `style` | 代码格式（不影响功能） |
| `refactor` | 重构（既非新功能也非修复） |
| `perf` | 性能优化 |
| `test` | 测试相关 |
| `build` | 构建系统或外部依赖 |
| `ci` | CI/CD 配置 |
| `chore` | 其他杂项 |
| `security` | 安全相关修复 |

### 示例

```
feat(firewall): 添加 IPv6 防火墙规则支持

- 新增 is_valid_ipv6() 验证函数
- 自动检测 ip6tables 可用性
- IPv6 地址使用 ip6tables 替代 iptables

Closes #123
```

```
fix(auth): 修复登录锁定时间计算错误

当用户连续登录失败时，锁定时间计算使用了错误的时区，
导致实际锁定时间与预期不符。

Fixes #456
```

```
docs(api): 添加 Swagger API 文档

集成 flasgger，为认证、健康检查、IDS 等关键端点
添加 OpenAPI 文档字符串。
```

## 项目结构概览

```
gatekeeper/
├── ai_engine/          # AI 引擎模块
│   ├── traffic_analyzer.py    # 流量分析
│   ├── anomaly_detector.py    # 异常检测
│   ├── model_manager.py       # 模型管理
│   ├── threat_intelligence.py # 威胁情报
│   └── vuln_scanner.py        # 漏洞扫描
├── alerting/           # 告警系统
│   ├── alert_manager.py       # 告警管理器
│   ├── email_alert.py         # 邮件告警
│   └── webhook_alert.py       # Webhook 告警
├── cli/                # 命令行界面
├── config/             # 配置管理
│   ├── settings.py            # 全局配置
│   ├── database.py            # 数据库配置
│   └── logging_config.py      # 日志配置
├── core/               # 核心模块
│   ├── app.py                 # 应用入口
│   ├── models.py              # 数据模型
│   ├── database.py            # 数据库管理
│   ├── scheduler.py           # 任务调度
│   └── audit.py               # 审计日志
├── network/            # 网络模块
│   ├── firewall.py            # 防火墙管理
│   ├── packet_capture.py      # 数据包捕获
│   ├── gateway.py             # 网关管理
│   └── dns_filter.py          # DNS 过滤
├── reports/            # 报表生成
├── scripts/            # 运维脚本
│   ├── cert-manager.sh        # SSL 证书管理
│   ├── backup.sh              # 数据备份
│   └── start.sh               # 启动脚本
├── security/           # 安全模块
│   ├── ids_engine.py          # IDS 引擎
│   ├── two_factor.py          # 双因素认证
│   └── compliance_checker.py  # 合规检查
├── web/                # Web 管理面板
│   ├── app.py                 # Flask 应用工厂
│   ├── templates/             # HTML 模板
│   ├── static/                # 静态资源
│   └── routes/                # 路由蓝图
│       ├── auth.py            # 认证路由
│       ├── health.py          # 健康检查
│       ├── ids.py             # IDS 管理
│       └── ...
├── tests/              # 测试
├── docs/               # 文档
├── data/               # 数据目录（数据库、证书等）
├── logs/               # 日志目录
├── models/             # AI 模型文件
├── requirements.txt    # Python 依赖
├── alembic.ini         # 数据库迁移配置
└── Dockerfile          # Docker 构建文件
```

## 获取帮助

如有任何问题，请通过 GitHub Issues 提交，或联系项目维护者。
