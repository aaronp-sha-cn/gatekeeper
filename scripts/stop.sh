#!/bin/bash
# ============================================================
# GateKeeper - 停止脚本
# ============================================================

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 项目目录
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="${PROJECT_DIR}/data/gatekeeper.pid"

echo -e "${GREEN}[INFO]${NC} 停止 GateKeeper..."

# 通过PID文件停止
if [ -f "${PID_FILE}" ]; then
    PID=$(cat "${PID_FILE}")

    if kill -0 "${PID}" 2>/dev/null; then
        # 发送SIGTERM信号（优雅关闭）
        kill -TERM "${PID}"

        # 等待进程退出
        TIMEOUT=30
        while [ $TIMEOUT -gt 0 ]; do
            if ! kill -0 "${PID}" 2>/dev/null; then
                break
            fi
            sleep 1
            TIMEOUT=$((TIMEOUT - 1))
        done

        # 如果进程仍在运行，强制终止
        if kill -0 "${PID}" 2>/dev/null; then
            echo -e "${YELLOW}[WARN]${NC} 进程未响应，强制终止..."
            kill -9 "${PID}" 2>/dev/null
        fi

        echo -e "${GREEN}[INFO]${NC} GateKeeper 已停止 (PID: ${PID})"
    else
        echo -e "${YELLOW}[WARN]${NC} 进程不存在 (PID: ${PID})"
    fi

    rm -f "${PID_FILE}"
else
    echo -e "${YELLOW}[WARN]${NC} PID文件不存在"
fi

# 额外检查：通过进程名查找并停止
PIDS=$(pgrep -f "core.app" 2>/dev/null || true)
if [ -n "${PIDS}" ]; then
    echo -e "${YELLOW}[WARN]${NC} 发现残留进程: ${PIDS}"
    for pid in ${PIDS}; do
        kill -TERM "${pid}" 2>/dev/null || true
    done
    sleep 2
    PIDS=$(pgrep -f "core.app" 2>/dev/null || true)
    if [ -n "${PIDS}" ]; then
        for pid in ${PIDS}; do
            kill -9 "${pid}" 2>/dev/null || true
        done
    fi
    echo -e "${GREEN}[INFO]${NC} 残留进程已清理"
fi

echo -e "${GREEN}[INFO]${NC} GateKeeper 已完全停止"
