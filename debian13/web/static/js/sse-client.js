/**
 * GateKeeper - SSE 客户端
 * 连接 Server-Sent Events 端点，接收实时告警和系统状态推送
 */

(function() {
    'use strict';

    var ALERT_COUNT_KEY = 'gatekeeper_sse_alert_count';
    var sseSource = null;
    var reconnectTimer = null;
    var reconnectDelay = 3000; // 初始重连延迟 3 秒
    var maxReconnectDelay = 30000; // 最大重连延迟 30 秒
    var currentDelay = reconnectDelay;

    // ===== DOM 元素引用 =====
    function getElements() {
        return {
            badge: document.getElementById('alertBadge'),
            sseStatusDot: document.getElementById('sseStatusDot'),
            sseStatusText: document.getElementById('sseStatusText'),
            toastContainer: document.getElementById('toastContainer'),
        };
    }

    // ===== 更新连接状态指示 =====
    function setConnected(connected) {
        var els = getElements();
        if (els.sseStatusDot) {
            if (connected) {
                els.sseStatusDot.classList.remove('disconnected');
            } else {
                els.sseStatusDot.classList.add('disconnected');
            }
        }
        if (els.sseStatusText) {
            els.sseStatusText.textContent = connected ? '已连接' : '已断开';
        }
    }

    // ===== 更新告警徽章 =====
    function updateAlertBadge() {
        var els = getElements();
        var count = getAlertCount();
        if (els.badge) {
            if (count > 0) {
                els.badge.style.display = 'inline-block';
                els.badge.textContent = count > 99 ? '99+' : count;
            } else {
                els.badge.style.display = 'none';
            }
        }
    }

    function getAlertCount() {
        try {
            return parseInt(localStorage.getItem(ALERT_COUNT_KEY) || '0', 10);
        } catch(e) {
            return 0;
        }
    }

    function incrementAlertCount() {
        var count = getAlertCount() + 1;
        try {
            localStorage.setItem(ALERT_COUNT_KEY, String(count));
        } catch(e) {}
        return count;
    }

    function resetAlertCount() {
        try {
            localStorage.setItem(ALERT_COUNT_KEY, '0');
        } catch(e) {}
    }

    // ===== Toast 通知 =====
    function showToast(title, message, level) {
        var els = getElements();
        if (!els.toastContainer) return;

        var toast = document.createElement('div');
        toast.className = 'toast toast-' + (level || 'info');

        var content = document.createElement('div');
        content.style.flex = '1';

        var titleEl = document.createElement('div');
        titleEl.style.fontWeight = '600';
        titleEl.style.marginBottom = '4px';
        titleEl.textContent = title || '新通知';

        var msgEl = document.createElement('div');
        msgEl.style.color = 'var(--text-muted)';
        msgEl.style.fontSize = '12px';
        msgEl.textContent = message || '';

        content.appendChild(titleEl);
        content.appendChild(msgEl);

        var closeBtn = document.createElement('button');
        closeBtn.className = 'toast-close';
        closeBtn.innerHTML = '&times;';
        closeBtn.onclick = function() {
            removeToast(toast);
        };

        toast.appendChild(content);
        toast.appendChild(closeBtn);
        els.toastContainer.appendChild(toast);

        // 自动移除 (8秒)
        setTimeout(function() {
            removeToast(toast);
        }, 8000);
    }

    function removeToast(toast) {
        if (!toast || !toast.parentNode) return;
        toast.style.animation = 'toastSlideOut 0.3s ease forwards';
        setTimeout(function() {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }

    // ===== 处理告警事件 =====
    function handleAlertEvent(data) {
        var level = data.level_value || data.level || 'medium';
        var title = data.title || '新告警';
        var desc = data.description || '';
        var sourceIp = data.source_ip || '';

        // 更新徽章计数
        incrementAlertCount();
        updateAlertBadge();

        // critical 和 high 级别显示 toast
        if (level === 'critical' || level === 'high') {
            var displayMsg = desc;
            if (sourceIp) {
                displayMsg = (desc ? desc + ' | ' : '') + '来源: ' + sourceIp;
            }
            showToast(title, displayMsg, level);
        }
    }

    // ===== 处理状态事件 =====
    function handleStatusEvent(data) {
        var status = data.status || '';
        var message = data.message || '';
        if (message) {
            showToast('系统状态变更', message, 'info');
        }
    }

    // ===== 连接 SSE =====
    function connectSSE() {
        if (sseSource) {
            sseSource.close();
        }

        // 检查是否在登录页面，避免未登录时连接
        if (window.location.pathname.indexOf('/auth/') === 0) {
            return;
        }

        try {
            sseSource = new EventSource('/events');
        } catch(e) {
            console.error('SSE连接创建失败:', e);
            scheduleReconnect();
            return;
        }

        sseSource.onopen = function() {
            console.log('[SSE] 已连接');
            setConnected(true);
            currentDelay = reconnectDelay; // 重置重连延迟
        };

        sseSource.addEventListener('alert', function(e) {
            try {
                var data = JSON.parse(e.data);
                handleAlertEvent(data.data || data);
            } catch(err) {
                console.error('[SSE] 解析告警事件失败:', err);
            }
        });

        sseSource.addEventListener('status', function(e) {
            try {
                var data = JSON.parse(e.data);
                handleStatusEvent(data.data || data);
            } catch(err) {
                console.error('[SSE] 解析状态事件失败:', err);
            }
        });

        sseSource.addEventListener('heartbeat', function(e) {
            // 心跳事件，无需处理
        });

        sseSource.onerror = function(e) {
            console.warn('[SSE] 连接错误');
            setConnected(false);

            if (sseSource) {
                sseSource.close();
                sseSource = null;
            }

            // EventSource 会自动重连，但如果 readyState 是 CLOSED 则手动重连
            scheduleReconnect();
        };
    }

    function scheduleReconnect() {
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
        }

        console.log('[SSE] 将在 ' + (currentDelay / 1000) + ' 秒后重连...');
        reconnectTimer = setTimeout(function() {
            connectSSE();
            // 指数退避
            currentDelay = Math.min(currentDelay * 1.5, maxReconnectDelay);
        }, currentDelay);
    }

    // ===== 页面可见性处理 =====
    function handleVisibilityChange() {
        if (document.hidden) {
            // 页面不可见时关闭连接节省资源
            if (sseSource) {
                sseSource.close();
                sseSource = null;
            }
        } else {
            // 页面可见时重新连接
            connectSSE();
        }
    }

    // ===== 导航到告警页面时重置计数 =====
    function handleNavigation() {
        if (window.location.pathname.indexOf('/alerts') === 0) {
            resetAlertCount();
            updateAlertBadge();
        }
    }

    // ===== 初始化 =====
    function init() {
        // 初始化徽章显示
        updateAlertBadge();

        // 连接 SSE
        connectSSE();

        // 监听页面可见性
        document.addEventListener('visibilitychange', handleVisibilityChange);

        // 监听导航变化（SPA或页面跳转）
        handleNavigation();

        // 在页面卸载时清理
        window.addEventListener('beforeunload', function() {
            if (sseSource) {
                sseSource.close();
            }
            if (reconnectTimer) {
                clearTimeout(reconnectTimer);
            }
        });
    }

    // DOM 加载完成后初始化
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // 暴露 resetAlertCount 到全局，供其他脚本调用
    window.GKSSE = {
        resetAlertCount: function() {
            resetAlertCount();
            updateAlertBadge();
        },
        getAlertCount: getAlertCount,
    };
})();
