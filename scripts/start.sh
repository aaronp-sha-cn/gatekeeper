#!/bin/bash
# ============================================================
# GateKeeper - 启动脚本
# ============================================================

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 项目目录
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"

# 检查虚拟环境
if [ ! -d "${VENV_DIR}" ]; then
    echo -e "${YELLOW}[WARN]${NC} 虚拟环境不存在，请先运行安装脚本"
    echo "用法: sudo ./scripts/install.sh"
    exit 1
fi

# 激活虚拟环境
source "${VENV_DIR}/bin/activate"

# 设置Python路径
export PYTHONPATH="${PROJECT_DIR}"

# 检查是否已在运行
PID_FILE="${PROJECT_DIR}/data/gatekeeper.pid"
if [ -f "${PID_FILE}" ]; then
    OLD_PID=$(cat "${PID_FILE}")
    if kill -0 "${OLD_PID}" 2>/dev/null; then
        echo -e "${YELLOW}[WARN]${NC} GateKeeper 已在运行 (PID: ${OLD_PID})"
        echo "如需重启，请先执行: ./scripts/stop.sh"
        exit 1
    else
        rm -f "${PID_FILE}"
    fi
fi

echo -e "${GREEN}[INFO]${NC} 启动 GateKeeper..."

# 启动应用
cd "${PROJECT_DIR}"
nohup python3 -m core.app --capture > "${PROJECT_DIR}/logs/gatekeeper.log" 2>&1 &
PID=$!

# 保存PID
echo "${PID}" > "${PID_FILE}"

# 等待启动
sleep 2

# 检查进程是否存活
if kill -0 "${PID}" 2>/dev/null; then
    echo -e "${GREEN}[INFO]${NC} GateKeeper 启动成功 (PID: ${PID})"
    echo ""
    echo "Web管理面板: https://localhost:8443"
    echo "日志文件:     ${PROJECT_DIR}/logs/gatekeeper.log"
    echo "停止命令:     ./scripts/stop.sh"
else
    echo -e "${YELLOW}[ERROR]${NC} GateKeeper 启动失败，请查看日志:"
    echo "  tail -f ${PROJECT_DIR}/logs/gatekeeper.log"
    rm -f "${PID_FILE}"
    exit 1
fi
