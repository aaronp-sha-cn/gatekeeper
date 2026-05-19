# ============================================================
# GateKeeper - ISO构建Docker镜像
# 使用方法: docker build -t aegis-builder . && docker run --rm -v $(pwd)/..:/build aegis-builder
# ============================================================

FROM debian:10

LABEL maintainer="GateKeeper Team"
LABEL description="GateKeeper ISO Builder for Debian 10 (Buster)"

# 安装构建工具
RUN apt-get update && apt-get install -y \
    xorriso \
    isolinux \
    syslinux-utils \
    squashfs-tools \
    dosfstools \
    cpio \
    gzip \
    wget \
    rsync \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /build

# 复制构建脚本
COPY build.sh /build.sh
RUN chmod +x /build.sh

# 入口点
ENTRYPOINT ["/build.sh"]
