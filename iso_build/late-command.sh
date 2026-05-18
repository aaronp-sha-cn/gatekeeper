#!/bin/sh
# ============================================================
# GateKeeper - Late Command
# 由 preseed late_command 在 Debian 安装过程中调用
# 运行环境：安装器环境（非 chroot），/target 是目标系统根目录
# ============================================================
#
# 关键修复说明：
# - 开头立即禁用 CD-ROM apt 源，防止 grub-pc 安装时从 CD-ROM 读取
# - 使用 /dev/sr0 挂载（isohybrid 后 USB 被内核识别为光驱设备）
# - 先配置 apt 源，再执行 postinstall.sh（确保 chroot 中 apt-get 可用）
# - chroot 执行 postinstall.sh 使用 /bin/sh（非 /bin/bash）
# ============================================================

# 调试日志
DEBUG_LOG="/target/tmp/late-command-debug.log"
echo "[$(date)] late_command started" >> "$DEBUG_LOG" 2>/dev/null || true

# 不要使用 set -e！任何步骤失败都不应阻止后续关键步骤执行
set +e

echo "[GateKeeper] ============================================"
echo "[GateKeeper] late_command: 开始执行安装后配置..."
echo "[GateKeeper] ============================================"

# ============================================================
# 0. 关键：立即禁用 CD-ROM apt 源
#    防止后续 grub-pc 安装时尝试从 CD-ROM 读取文件导致失败
# ============================================================
echo "[GateKeeper] [0] 禁用 CD-ROM apt 源..."
rm -f /target/etc/apt/sources.list.d/cdrom.list 2>/dev/null || true
if [ -f /target/etc/apt/sources.list ]; then
    sed -i '/^deb cdrom:/d' /target/etc/apt/sources.list 2>/dev/null || true
    sed -i '/^deb-src cdrom:/d' /target/etc/apt/sources.list 2>/dev/null || true
fi
# 清空 sources.list，防止残留的 cdrom 条目
> /target/etc/apt/sources.list 2>/dev/null || true
# 同时禁用安装器环境的 CD-ROM 源
rm -f /etc/apt/sources.list.d/cdrom.list 2>/dev/null || true
echo "[GateKeeper] [0] CD-ROM apt 源已禁用"

# ============================================================
# 1. 配置 apt 源为 archive.debian.org
#    必须在 postinstall.sh 之前配置，确保 chroot 中 apt-get 可用
# ============================================================
echo "[GateKeeper] [1] 配置 apt 源..."
cat > /target/etc/apt/sources.list << 'APT_EOF'
deb http://archive.debian.org/debian buster main contrib non-free
APT_EOF
echo "[GateKeeper] [1] apt 源已配置为 archive.debian.org"

# ============================================================
# 2. 复制 gatekeeper.tar.gz 到目标系统并解压
# ============================================================
echo "[GateKeeper] [2] 复制并解压项目文件..."

if [ -f /cdrom/gatekeeper.tar.gz ]; then
    cp /cdrom/gatekeeper.tar.gz /target/tmp/gatekeeper.tar.gz
    echo "[GateKeeper] [2] tar.gz 已复制"
else
    echo "[GateKeeper] [2] ERROR: /cdrom/gatekeeper.tar.gz 未找到"
    exit 1
fi

if [ -f /target/tmp/gatekeeper.tar.gz ]; then
    tar xzf /target/tmp/gatekeeper.tar.gz -C /target/
    echo "[GateKeeper] [2] 解压完成"
else
    echo "[GateKeeper] [2] ERROR: tar.gz 文件未找到"
    exit 1
fi

if [ -d /target/opt/gatekeeper ]; then
    echo "[GateKeeper] [2] 目录结构验证通过: /opt/gatekeeper"
else
    echo "[GateKeeper] [2] ERROR: 解压后目录不存在"
    exit 1
fi

# 设置脚本权限
chmod +x /target/opt/gatekeeper/scripts/*.sh 2>/dev/null || true
echo "[GateKeeper] [2] 脚本权限已设置"

# ============================================================
# 3. 配置网络接口（eth0 DHCP）
# ============================================================
echo "[GateKeeper] [3] 配置网络接口..."
cat > /target/etc/network/interfaces << 'NET_EOF'
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# Primary network interface (eth0) - DHCP
auto eth0
iface eth0 inet dhcp

# Secondary network interface (eth1) - can be configured manually
# auto eth1
# iface eth1 inet static
#     address 192.168.2.1
#     netmask 255.255.255.0
NET_EOF
echo "[GateKeeper] [3] 网络接口已配置（eth0 DHCP）"

# ============================================================
# 4. 配置 GRUB（传统网卡命名 + 背景图片）
# ============================================================
echo "[GateKeeper] [4] 配置 GRUB..."
if [ -f /target/etc/default/grub ]; then
    # 配置内核参数：传统网卡命名
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /target/etc/default/grub; then
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=".*"/GRUB_CMDLINE_LINUX_DEFAULT="net.ifnames=0 biosdevname=0 quiet"/' /target/etc/default/grub
    else
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="net.ifnames=0 biosdevname=0 quiet"' >> /target/etc/default/grub
    fi

    if grep -q '^GRUB_CMDLINE_LINUX=' /target/etc/default/grub; then
        sed -i 's/^GRUB_CMDLINE_LINUX=".*"/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/' /target/etc/default/grub
    else
        echo 'GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"' >> /target/etc/default/grub
    fi

    # 配置 GRUB 背景图片
    if [ -f /cdrom/grub_background.png ] || [ -f /cdrom/grub_background.jpg ] || [ -f /cdrom/grub_background.tga ]; then
        mkdir -p /target/boot/grub
        for ext in png jpg tga; do
            if [ -f /cdrom/grub_background.${ext} ]; then
                cp /cdrom/grub_background.${ext} /target/boot/grub/grub_background.${ext}
                break
            fi
        done
        sed -i 's|^#GRUB_BACKGROUND=.*|GRUB_BACKGROUND=/boot/grub/grub_background.png|' /target/etc/default/grub
        if ! grep -q "^GRUB_BACKGROUND=" /target/etc/default/grub; then
            echo 'GRUB_BACKGROUND=/boot/grub/grub_background.png' >> /target/etc/default/grub
        fi
        # 主题颜色
        sed -i 's|^#GRUB_COLOR_NORMAL=.*|GRUB_COLOR_NORMAL="white/black"|' /target/etc/default/grub
        sed -i 's|^#GRUB_COLOR_HIGHLIGHT=.*|GRUB_COLOR_HIGHLIGHT="cyan/black"|' /target/etc/default/grub
        if ! grep -q "^GRUB_COLOR_NORMAL=" /target/etc/default/grub; then
            echo 'GRUB_COLOR_NORMAL="white/black"' >> /target/etc/default/grub
            echo 'GRUB_COLOR_HIGHLIGHT="cyan/black"' >> /target/etc/default/grub
        fi
        echo "[GateKeeper] [4] GRUB 背景图片已配置"
    fi

    # 更新 GRUB 配置
    if [ -f /target/usr/sbin/update-grub ]; then
        chroot /target /usr/sbin/update-grub 2>/dev/null || true
        echo "[GateKeeper] [4] GRUB 配置已更新"
    fi
fi

# ============================================================
# 5. 配置 Plymouth 启动画面
# ============================================================
echo "[GateKeeper] [5] 配置 Plymouth 启动画面..."
if [ -f /cdrom/plymouth_background.png ] || [ -f /cdrom/plymouth_background.jpg ]; then
    chroot /target apt-get install -y plymouth plymouth-themes 2>/dev/null || true

    GK_PLYMOUTH_DIR="/target/usr/share/plymouth/themes/gatekeeper"
    mkdir -p "${GK_PLYMOUTH_DIR}"

    for ext in png jpg; do
        if [ -f /cdrom/plymouth_background.${ext} ]; then
            cp /cdrom/plymouth_background.${ext} "${GK_PLYMOUTH_DIR}/background.${ext}"
            break
        fi
    done

    cat > "${GK_PLYMOUTH_DIR}/gatekeeper.plymouth" << 'PLYMOUTH_THEME'
[Plymouth Theme]
Name=GateKeeper
Description=GateKeeper AI Security Network Defense System
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/gatekeeper
ScriptFile=/usr/share/plymouth/themes/gatekeeper/gatekeeper.script
PLYMOUTH_THEME

    cat > "${GK_PLYMOUTH_DIR}/gatekeeper.script" << 'PLYMOUTH_SCRIPT'
# GateKeeper Plymouth Boot Script
wallpaper_image = Image("background.png");
screen_width = Window.GetWidth();
screen_height = Window.GetHeight();
rescaled_wallpaper_image = wallpaper_image.Scale(screen_width, screen_height);
wallpaper_sprite = Sprite(rescaled_wallpaper_image);
wallpaper_sprite.SetPosition(0, 0);

progress_box = Image(screen_width * 0.4, 6);
progress_box = progress_box.Rotate(0);
progress_bar = Image(screen_width * 0.4, 6);
progress_bar = progress_bar.Rotate(0);

progress_box_x = (screen_width - progress_box.GetWidth()) / 2;
progress_box_y = screen_height * 0.75;
progress_bar_x = progress_box_x;
progress_bar_y = progress_box_y;

progress_box_sprite = Sprite(progress_box);
progress_box_sprite.SetPosition(progress_box_x, progress_box_y);

progress_bar_sprite = Sprite();
progress_bar_sprite.SetPosition(progress_bar_x, progress_bar_y);

fun refresh_callback () {
    progress_bar_sprite.SetPosition(progress_bar_x, progress_bar_y);
}
Plymouth.SetRefreshFunction(refresh_callback);

fun display_normal_callback () {
    progress_box_sprite.SetOpacity(1);
    progress_bar_sprite.SetOpacity(1);
}

fun display_password_callback (prompt, bullets) {
    progress_box_sprite.SetOpacity(0.3);
    progress_bar_sprite.SetOpacity(0.3);
}
Plymouth.SetDisplayNormalFunction(display_normal_callback);
Plymouth.SetDisplayPasswordFunction(display_password_callback);

fun progress_callback (duration, progress) {
    if (progress_bar.GetWidth() > 0) {
        bar_width = progress_box.GetWidth() * (progress / 100.0);
        scaled_bar = progress_bar.Scale(bar_width, progress_bar.GetHeight());
        progress_bar_sprite.SetImage(scaled_bar);
    }
}
Plymouth.SetProgressFunction(progress_callback);
PLYMOUTH_SCRIPT

    chroot /target /usr/sbin/plymouth-set-default-theme -R gatekeeper 2>/dev/null || true
    chroot /target /usr/sbin/update-initramfs -u 2>/dev/null || true
    echo "[GateKeeper] [5] Plymouth 启动画面已配置"
else
    echo "[GateKeeper] [5] 未找到 Plymouth 背景图片，跳过"
fi

# ============================================================
# 6. 品牌标识（hostname、登录提示、MOTD）
# ============================================================
echo "[GateKeeper] [6] 应用品牌标识..."

echo "gatekeeper" > /target/etc/hostname
sed -i 's/127.0.1.1.*/127.0.1.1\tgatekeeper/' /target/etc/hosts

cat > /target/etc/issue << 'ISSUE_EOF'
GateKeeper - AI Security Network Defense System
Kernel \r on an \m (\l)

ISSUE_EOF

echo "GateKeeper - AI Security Network Defense System" > /target/etc/issue.net

if [ -f /target/etc/ssh/sshd_config ]; then
    sed -i 's/^#\?Banner .*/Banner \/etc\/issue.net/' /target/etc/ssh/sshd_config
fi

cat > /target/etc/motd << 'MOTD_EOF'

 #####                      #    #
#     #   ##   ##### ###### #   #  ###### ###### #####  ###### #####
#        #  #    #   #      #  #   #      #      #    # #      #    #
#  #### #    #   #   #####  ###    #####  #####  #    # #####  #    #
#     # ######   #   #      #  #   #      #      #####  #      #####
#     # #    #   #   #      #   #  #      #      #      #      #   #
 #####  #    #   #   ###### #    # ###### ###### #      ###### #    #

  GateKeeper - AI Security Network Defense System v1.2.0

  Web Interface: https://\4: \n
  Documentation: /opt/gatekeeper/docs/

MOTD_EOF

rm -f /target/etc/motd.d/* 2>/dev/null || true
echo "[GateKeeper] [6] 品牌标识已应用"

# ============================================================
# 7. 执行 postinstall.sh（在 chroot 中）
#    关键：使用 /bin/sh 执行（非 /bin/bash）
#    此时 apt 源已在步骤 1 配置完成，postinstall.sh 可正常 apt-get update
# ============================================================
echo "[GateKeeper] [7] 执行 postinstall.sh（chroot）..."
POSTINSTALL_SUCCESS=0
if [ -f /target/opt/gatekeeper/scripts/postinstall.sh ]; then
    # 确保 postinstall.sh 可执行
    chmod +x /target/opt/gatekeeper/scripts/postinstall.sh
    # 使用 /bin/sh 执行（chroot 中可能还没有 bash）
    if chroot /target /bin/sh /opt/gatekeeper/scripts/postinstall.sh; then
        echo "[GateKeeper] [7] postinstall.sh 执行成功"
        POSTINSTALL_SUCCESS=1
    else
        echo "[GateKeeper] [7] WARNING: postinstall.sh 执行失败，使用后备方案"
    fi
else
    echo "[GateKeeper] [7] WARNING: postinstall.sh 未找到"
fi

# 后备方案：如果 postinstall.sh 失败，手动创建必要文件
if [ "$POSTINSTALL_SUCCESS" -eq 0 ]; then
    echo "[GateKeeper] [7] 执行后备方案..."
    # 创建 systemd 服务
    mkdir -p /target/etc/systemd/system
    mkdir -p /target/etc/systemd/system/multi-user.target.wants
    cat > /target/etc/systemd/system/gatekeeper-setup.service << 'SERVICE_EOF'
[Unit]
Description=GateKeeper - First Time Setup
After=network-online.target network.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/gatekeeper/scripts/first-start.sh
TimeoutStartSec=1800
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty0
TTYReset=yes
TTYVHangup=no

[Install]
WantedBy=multi-user.target
SERVICE_EOF
    # 启用服务
    ln -sf /target/etc/systemd/system/gatekeeper-setup.service \
        /target/etc/systemd/system/multi-user.target.wants/gatekeeper-setup.service
    # 创建安装标记
    touch /target/opt/gatekeeper/.install_pending
    echo "[GateKeeper] [7] 后备方案执行完成"
fi

# ============================================================
# 8. 添加 rc.local 后备触发（确保 first-start 一定被执行）
#    即使 systemd 服务未启动，rc.local 也会在启动时执行
# ============================================================
echo "[GateKeeper] [8] 添加 rc.local 后备触发..."
mkdir -p /target/etc/rc.local.d
cat > /target/etc/rc.local << 'RCLOCAL_EOF'
#!/bin/sh
# GateKeeper - rc.local 后备触发
# 如果 first-start.sh 尚未执行（.install_pending 存在），则执行
if [ -f /opt/gatekeeper/.install_pending ]; then
    echo "[$(date)] rc.local: 检测到 .install_pending，启动 first-start.sh" > /opt/gatekeeper/logs/rc-local-trigger.log
    /bin/sh /opt/gatekeeper/scripts/first-start.sh >> /opt/gatekeeper/logs/rc-local-trigger.log 2>&1
fi
exit 0
RCLOCAL_EOF
chmod +x /target/etc/rc.local

# 同时启用 rc-local 服务
if [ -f /target/etc/systemd/system/rc-local.service ] || [ -f /target/lib/systemd/system/rc-local.service ]; then
    ln -sf /target/lib/systemd/system/rc-local.service \
        /target/etc/systemd/system/multi-user.target.wants/rc-local.service 2>/dev/null || true
fi

# ============================================================
# 9. 清理临时文件
# ============================================================
echo "[GateKeeper] [9] 清理临时文件..."
rm -f /target/tmp/gatekeeper.tar.gz
rm -f /target/tmp/late-command.sh

echo "[GateKeeper] ============================================"
echo "[GateKeeper] late_command: 全部完成"
echo "[GateKeeper] ============================================"
exit 0
