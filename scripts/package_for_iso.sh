#!/bin/bash
# ============================================================
# GateKeeper - 打包脚本
# 将更新后的代码打包为tar.gz，用于ISO构建
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${PROJECT_DIR}/iso_build/build"
OUTPUT_PKG="${OUTPUT_DIR}/gatekeeper.tar.gz"

log_step "[1/3] 创建输出目录..."
mkdir -p "${OUTPUT_DIR}"

log_step "[2/3] 准备打包文件..."
TEMP_DIR=$(mktemp -d)

# 创建正确的目录结构: opt/gatekeeper/
mkdir -p "${TEMP_DIR}/opt/gatekeeper"

# 使用rsync复制文件到 opt/gatekeeper/
if command -v rsync &> /dev/null; then
    rsync -av \
        --exclude='iso_build' \
        --exclude='venv' \
        --exclude='.git' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        --exclude='*.iso' \
        --exclude='*.zip' \
        --exclude='.uploads' \
        --exclude='logs/*.log' \
        "${PROJECT_DIR}/" "${TEMP_DIR}/opt/gatekeeper/"
else
    cp -r "${PROJECT_DIR}/"* "${TEMP_DIR}/opt/gatekeeper/" 2>/dev/null || true
    rm -rf "${TEMP_DIR}/opt/gatekeeper/iso_build" 2>/dev/null || true
    rm -rf "${TEMP_DIR}/opt/gatekeeper/venv" 2>/dev/null || true
    rm -rf "${TEMP_DIR}/opt/gatekeeper/.git" 2>/dev/null || true
    find "${TEMP_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "${TEMP_DIR}" -name "*.pyc" -delete 2>/dev/null || true
fi

# 确保脚本可执行
chmod +x "${TEMP_DIR}/opt/gatekeeper/scripts/"*.sh 2>/dev/null || true

log_step "[3/3] 创建tar.gz包..."
cd "${TEMP_DIR}"
tar czf "${OUTPUT_PKG}" opt

# 清理临时目录
rm -rf "${TEMP_DIR}"

log_info "打包完成!"
echo ""
echo "输出文件: ${OUTPUT_PKG}"
echo "文件大小: $(du -h ${OUTPUT_PKG} 2>/dev/null | cut -f1 || echo '未知')"
echo "MD5校验:  $(md5sum ${OUTPUT_PKG} 2>/dev/null | cut -d' ' -f1 || echo '未知')"
echo ""
echo -e "${GREEN}此tar.gz包可用于ISO构建${NC}"
echo "解压后目录结构: opt/gatekeeper/"
