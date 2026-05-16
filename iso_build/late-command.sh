#!/bin/sh
# ============================================================
# GateKeeper - Late Command Wrapper
# Called by preseed late_command during Debian installation
# Runs inside the installer environment (NOT chroot)
# ============================================================

echo "[GateKeeper] late_command: Copying files to target system..."

# 1. Copy tar.gz to target /tmp
if [ -f /cdrom/gatekeeper.tar.gz ]; then
    cp /cdrom/gatekeeper.tar.gz /target/tmp/gatekeeper.tar.gz
    echo "[GateKeeper] tar.gz copied successfully"
else
    echo "[GateKeeper] ERROR: /cdrom/gatekeeper.tar.gz not found"
    exit 1
fi

# 2. Extract to target root
if [ -f /target/tmp/gatekeeper.tar.gz ]; then
    tar xzf /target/tmp/gatekeeper.tar.gz -C /target/
    echo "[GateKeeper] Extraction complete"
else
    echo "[GateKeeper] ERROR: tar.gz file not found"
    exit 1
fi

# 3. Verify extraction
if [ -d /target/opt/gatekeeper ]; then
    echo "[GateKeeper] Directory structure OK: /opt/gatekeeper"
else
    echo "[GateKeeper] ERROR: Directory not found after extraction"
    exit 1
fi

# 4. Set script permissions
chmod +x /target/opt/gatekeeper/scripts/*.sh 2>/dev/null || true
echo "[GateKeeper] Script permissions set"

# 5. Configure GRUB for traditional network interface naming (eth0, eth1, ...)
if [ -f /target/etc/default/grub ]; then
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 splash"/' /target/etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="net.ifnames=0 biosdevname=0 splash quiet"/' /target/etc/default/grub
    if ! grep -q "net.ifnames=0" /target/etc/default/grub; then
        sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 net.ifnames=0 biosdevname=0 splash"/' /target/etc/default/grub 2>/dev/null || true
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 net.ifnames=0 biosdevname=0 splash quiet"/' /target/etc/default/grub 2>/dev/null || true
    fi

    # 5.1. Configure GRUB background image
    if [ -f /cdrom/grub_background.png ] || [ -f /cdrom/grub_background.jpg ] || [ -f /cdrom/grub_background.tga ]; then
        mkdir -p /target/boot/grub
        for ext in png jpg tga; do
            if [ -f /cdrom/grub_background.${ext} ]; then
                cp /cdrom/grub_background.${ext} /target/boot/grub/grub_background.${ext}
                break
            fi
        done
        # Set GRUB background and theme colors
        sed -i 's|^#GRUB_BACKGROUND=.*|GRUB_BACKGROUND=/boot/grub/grub_background.png|' /target/etc/default/grub
        if ! grep -q "^GRUB_BACKGROUND=" /target/etc/default/grub; then
            echo 'GRUB_BACKGROUND=/boot/grub/grub_background.png' >> /target/etc/default/grub
        fi
        # Set GRUB theme colors (dark background, white text, cyan highlight)
        sed -i 's|^#GRUB_COLOR_NORMAL=.*|GRUB_COLOR_NORMAL="white/black"|' /target/etc/default/grub
        sed -i 's|^#GRUB_COLOR_HIGHLIGHT=.*|GRUB_COLOR_HIGHLIGHT="cyan/black"|' /target/etc/default/grub
        if ! grep -q "^GRUB_COLOR_NORMAL=" /target/etc/default/grub; then
            echo 'GRUB_COLOR_NORMAL="white/black"' >> /target/etc/default/grub
            echo 'GRUB_COLOR_HIGHLIGHT="cyan/black"' >> /target/etc/default/grub
        fi
        # Hide GRUB menu timeout (show background briefly)
        if ! grep -q "^GRUB_TIMEOUT=" /target/etc/default/grub; then
            sed -i 's|^GRUB_TIMEOUT=.*|GRUB_TIMEOUT=3|' /target/etc/default/grub 2>/dev/null || true
        fi
        echo "[GateKeeper] GRUB background image configured"
    fi

    echo "[GateKeeper] GRUB interface naming configured (eth0, eth1, ...)"
    
    # Update GRUB configuration to apply changes
    if [ -f /target/usr/sbin/update-grub ]; then
        chroot /target /usr/sbin/update-grub 2>/dev/null || true
        echo "[GateKeeper] GRUB configuration updated"
    fi
fi

# 5.5. Configure apt sources for Debian 10 archive
# Note: Debian 10 (Buster) is EOL. Security updates are merged into the main archive.
cat > /target/etc/apt/sources.list << 'EOF'
deb http://archive.debian.org/debian buster main contrib non-free
EOF
echo "[GateKeeper] APT sources configured for Debian 10 archive"

# 6. Configure network interfaces for eth0, eth1, ...
if [ -f /target/etc/network/interfaces ]; then
    cat > /target/etc/network/interfaces << 'EOF'
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

# Additional interfaces can be added as needed
# auto eth2
# iface eth2 inet manual
EOF
    echo "[GateKeeper] Network interfaces configured for eth0, eth1, ..."
fi

# 7. Configure Plymouth boot splash screen
echo "[GateKeeper] Configuring Plymouth boot splash..."
if [ -f /cdrom/plymouth_background.png ] || [ -f /cdrom/plymouth_background.jpg ]; then
    # Install plymouth if available (may already be installed)
    chroot /target apt-get install -y plymouth plymouth-themes 2>/dev/null || true

    # Create GateKeeper plymouth theme
    GK_PLYMOUTH_DIR="/target/usr/share/plymouth/themes/gatekeeper"
    mkdir -p "${GK_PLYMOUTH_DIR}"

    # Copy background image
    for ext in png jpg; do
        if [ -f /cdrom/plymouth_background.${ext}; then
            cp /cdrom/plymouth_background.${ext} "${GK_PLYMOUTH_DIR}/background.${ext}"
            BG_FILE="background.${ext}"
            break
        fi
    done

    # Create plymouth theme script
    cat > "${GK_PLYMOUTH_DIR}/gatekeeper.plymouth" << 'PLYMOUTH_THEME'
[Plymouth Theme]
Name=GateKeeper
Description=GateKeeper AI Security Network Defense System
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/gatekeeper
ScriptFile=/usr/share/plymouth/themes/gatekeeper/gatekeeper.script
PLYMOUTH_THEME

    # Create plymouth script
    cat > "${GK_PLYMOUTH_DIR}/gatekeeper.script" << 'PLYMOUTH_SCRIPT'
# GateKeeper Plymouth Boot Script
wallpaper_image = Image("background.png");
screen_width = Window.GetWidth();
screen_height = Window.GetHeight();
rescaled_wallpaper_image = wallpaper_image.Scale(screen_width, screen_height);
wallpaper_sprite = Sprite(rescaled_wallpaper_image);
wallpaper_sprite.SetPosition(0, 0);

# Progress bar
progress_box = Image("progress_box.png");
progress_bar = Image("progress_bar.png");

# If progress images don't exist, create simple ones
if (progress_box == NULL) {
    progress_box = Image(screen_width * 0.4, 6);
    progress_box = progress_box.Rotate(0);
}

if (progress_bar == NULL) {
    progress_bar = Image(screen_width * 0.4, 6);
    progress_bar = progress_bar.Rotate(0);
}

progress_box_x = (screen_width - progress_box.GetWidth()) / 2;
progress_box_y = screen_height * 0.75;
progress_bar_x = progress_box_x;
progress_bar_y = progress_box_y;

progress_box_sprite = Sprite(progress_box);
progress_box_sprite.SetPosition(progress_box_x, progress_box_y);

progress_bar_sprite = Sprite();
progress_bar_sprite.SetPosition(progress_bar_x, progress_bar_y);

fun refresh_callback ()
{
    progress_bar_sprite.SetPosition(progress_bar_x, progress_bar_y);
}

Plymouth.SetRefreshFunction(refresh_callback);

fun display_normal_callback ()
{
    progress_box_sprite.SetOpacity(1);
    progress_bar_sprite.SetOpacity(1);
}

fun display_password_callback (prompt, bullets)
{
    progress_box_sprite.SetOpacity(0.3);
    progress_bar_sprite.SetOpacity(0.3);
}

Plymouth.SetDisplayNormalFunction(display_normal_callback);
Plymouth.SetDisplayPasswordFunction(display_password_callback);

fun progress_callback (duration, progress)
{
    if (progress_bar.GetWidth() > 0) {
        bar_width = progress_box.GetWidth() * (progress / 100.0);
        scaled_bar = progress_bar.Scale(bar_width, progress_bar.GetHeight());
        progress_bar_sprite.SetImage(scaled_bar);
    }
}

Plymouth.SetProgressFunction(progress_callback);
PLYMOUTH_SCRIPT

    # Set GateKeeper as default plymouth theme
    chroot /target /usr/sbin/plymouth-set-default-theme -R gatekeeper 2>/dev/null || true

    # Update initramfs to include plymouth
    chroot /target /usr/sbin/update-initramfs -u 2>/dev/null || true

    echo "[GateKeeper] Plymouth boot splash configured"
else
    echo "[GateKeeper] No Plymouth background found, skipping boot splash"
fi

# 8. Execute postinstall.sh in chroot
if [ -f /target/opt/gatekeeper/scripts/postinstall.sh ]; then
    chroot /target /bin/bash /opt/gatekeeper/scripts/postinstall.sh
    echo "[GateKeeper] postinstall.sh completed"
else
    echo "[GateKeeper] WARNING: postinstall.sh not found, skipping"
fi

# 8. Cleanup temp files
rm -f /target/tmp/gatekeeper.tar.gz

echo "[GateKeeper] late_command: Done"
exit 0
