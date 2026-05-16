/**
 * 镇关 (GateKeeper) - 前端JavaScript
 * 提供通用的前端工具函数
 */

// ===== 时间格式化 =====
function formatTime(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now - date;

    if (diff < 60000) return '刚刚';
    if (diff < 3600000) return Math.floor(diff / 60000) + '分钟前';
    if (diff < 86400000) return Math.floor(diff / 3600000) + '小时前';
    if (diff < 604800000) return Math.floor(diff / 86400000) + '天前';

    const pad = (n) => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// ===== 字节格式化 =====
function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + units[i];
}

// ===== 数字格式化 =====
function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    return num.toLocaleString('zh-CN');
}

// ===== API请求封装 =====
async function apiRequest(url, options = {}) {
    const defaults = {
        headers: {
            'Content-Type': 'application/json',
        },
    };

    // 添加CSRF token
    const csrfToken = document.querySelector('meta[name="csrf-token"]');
    if (csrfToken) {
        defaults.headers['X-CSRFToken'] = csrfToken.getAttribute('content');
    }

    const config = { ...defaults, ...options, headers: { ...defaults.headers, ...options.headers } };

    try {
        const response = await fetch(url, config);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || `HTTP ${response.status}`);
        }

        return data;
    } catch (error) {
        console.error('API请求失败:', error);
        throw error;
    }
}

// ===== 登出 =====
function logout() {
    fetch('/auth/logout', { method: 'POST' })
        .then(() => { window.location.href = '/auth/login'; });
}

// ===== 更新时钟 =====
let _systemStartTime = null;
const _UPTIME_CACHE_KEY = 'gatekeeper_boot_time';

// 从后端获取系统启动时间，缓存到 localStorage 避免页面切换时重置
function fetchSystemBootTime() {
    // 先同步读取缓存，确保第一次 updateClock 就有值
    const cached = localStorage.getItem(_UPTIME_CACHE_KEY);
    if (cached) {
        _systemStartTime = parseInt(cached, 10);
    }
    // 异步从后端获取最新值（每次页面加载都验证，防止系统重启后缓存过期）
    fetch('/api/system-monitor')
        .then(r => r.json())
        .then(data => {
            if (data.status === 'ok' && data.data && data.data.boot_time) {
                const serverBootMs = data.data.boot_time * 1000;
                // 如果缓存值与服务器不一致（系统重启过），更新缓存
                if (!cached || Math.abs(parseInt(cached, 10) - serverBootMs) > 5000) {
                    _systemStartTime = serverBootMs;
                    localStorage.setItem(_UPTIME_CACHE_KEY, String(_systemStartTime));
                }
            } else if (!_systemStartTime) {
                _systemStartTime = Date.now();
                localStorage.setItem(_UPTIME_CACHE_KEY, String(_systemStartTime));
            }
        })
        .catch(() => {
            if (!_systemStartTime) {
                _systemStartTime = Date.now();
                localStorage.setItem(_UPTIME_CACHE_KEY, String(_systemStartTime));
            }
        });
}

function updateClock() {
    const el = document.getElementById('current-time');
    if (el) {
        const now = new Date();
        const pad = (n) => String(n).padStart(2, '0');
        const year = now.getFullYear();
        const month = pad(now.getMonth() + 1);
        const day = pad(now.getDate());
        const weekDays = ['日', '一', '二', '三', '四', '五', '六'];
        const weekDay = weekDays[now.getDay()];
        const time = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
        el.textContent = `${year}-${month}-${day} 周${weekDay} ${time}`;
    }

    // 更新系统运行时间
    const statusEl = document.getElementById('system-status');
    if (statusEl && _systemStartTime) {
        const elapsed = Math.floor((Date.now() - _systemStartTime) / 1000);
        const days = Math.floor(elapsed / 86400);
        const hours = Math.floor((elapsed % 86400) / 3600);
        const minutes = Math.floor((elapsed % 3600) / 60);
        const seconds = elapsed % 60;
        let uptimeStr = '系统运行中';
        if (days > 0) {
            uptimeStr += ` ${days}天${hours}时${minutes}分`;
        } else if (hours > 0) {
            uptimeStr += ` ${hours}时${minutes}分${seconds}秒`;
        } else {
            uptimeStr += ` ${minutes}分${seconds}秒`;
        }
        statusEl.textContent = uptimeStr;
    }
}

// ===== 通知 =====
function showNotification(message, type = 'info') {
    const colors = {
        info: 'var(--info)',
        success: 'var(--success)',
        warning: 'var(--warning)',
        error: 'var(--danger)',
    };

    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        background: var(--bg-card);
        border: 1px solid ${colors[type]};
        border-radius: 8px;
        color: var(--text);
        font-size: 14px;
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// showToast 作为 showNotification 的别名，兼容各模板
function showToast(message, type) {
    showNotification(message, type || 'info');
}

// ===== 确认对话框 =====
function confirmAction(message) {
    return new Promise((resolve) => {
        resolve(window.confirm(message));
    });
}

// ===== 初始化 =====
document.addEventListener('DOMContentLoaded', function() {
    // 先同步读取缓存，确保第一次 updateClock 就有值
    const cached = localStorage.getItem(_UPTIME_CACHE_KEY);
    if (cached) {
        _systemStartTime = parseInt(cached, 10);
    }
    // 异步获取最新值（会更新缓存）
    fetchSystemBootTime();
    // 立即更新一次显示
    updateClock();
    // 每秒更新
    setInterval(updateClock, 1000);
});
