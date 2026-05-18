#!/bin/bash
# GateKeeper - 服务启动入口脚本
# 由 systemd gatekeeper.service 调用

cd /opt/gatekeeper || { echo "ERROR: Cannot cd to /opt/gatekeeper"; exit 1; }

# 检查 venv 是否存在
if [ ! -d "venv" ]; then
    echo "ERROR: venv directory not found"
    exit 1
fi

if [ ! -f "venv/bin/python3" ]; then
    echo "ERROR: venv/bin/python3 not found"
    exit 1
fi

# 检查关键依赖
if ! /opt/gatekeeper/venv/bin/python3 -c "import flask, sqlalchemy" 2>/dev/null; then
    echo "ERROR: Required Python packages not installed"
    echo "Please run: /opt/gatekeeper/scripts/first-start.sh"
    exit 1
fi

export PYTHONPATH=/opt/gatekeeper

# 启动应用
exec /opt/gatekeeper/venv/bin/python3 -c "
import sys
import traceback
sys.path.insert(0, '/opt/gatekeeper')
try:
    from core.app import main
    main()
except Exception as e:
    print('ERROR: {}'.format(e), file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)
"
