"""
GateKeeper - AI安全网络防御系统
基于Python的智能网络安全防御平台
Debian 13 (Trixie) / Python 3.13
"""

from setuptools import setup, find_packages

try:
    long_description=open("README.md", "r", encoding="utf-8").read()
except FileNotFoundError:
    long_description=""

setup(
    name="gatekeeper",
    version="1.3.0",
    description="AI安全网络防御系统 - 智能网络安全防御平台",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="GateKeeper Team",
    author_email="security@gatekeeper.local",
    url="https://github.com/gatekeeper-security/gatekeeper",
    license="MIT",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*", "iso_build*"]),
    include_package_data=True,
    install_requires=[
        "flask>=2.0.0",
        "flask-login>=0.6.0",
        "flask-wtf>=1.0.0",
        "flask-limiter>=3.0.0",
        "werkzeug>=2.3.0",
        "markupsafe>=2.1.0",
        "sqlalchemy>=2.0.0",
        "alembic>=1.8.0",
        "scapy>=2.5.0",
        "dpkt>=1.9.8",
        "scikit-learn>=1.3.0",
        "numpy>=1.25.0",
        "pandas>=2.0.0",
        "joblib>=1.3.0",
        "schedule>=1.2.0",
        "apscheduler>=3.10.0",
        "paramiko>=3.0.0",
        "reportlab>=4.0.0",
        "email-validator>=2.0.0",
        "prompt-toolkit>=3.0.36",
        "psutil>=5.9.0",
        "cryptography>=41.0.0",
        "requests>=2.31.0",
        "ldap3>=2.9.0",
        "flasgger>=0.9.7",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "mitm": [
            "mitmproxy>=10.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "gatekeeper=core.app:main",
            "gk-cli=cli.main:main",
            "gk-junos=cli.junos_cli:main",
            "gk-cisco=cli.cisco_cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    zip_safe=False,
)
