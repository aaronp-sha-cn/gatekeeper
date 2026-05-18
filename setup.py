"""
GateKeeper - AI安全网络防御系统
基于Python的智能网络安全防御平台
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
    python_requires=">=3.7",
    packages=find_packages(exclude=["tests*", "iso_build*"]),
    include_package_data=True,
    install_requires=[
        "flask>=1.0.0",
        "flask-login>=0.5.0",
        "flask-wtf>=0.14.0",
        "flask-limiter>=1.4.0",
        "werkzeug>=1.0.0",
        "markupsafe>=1.1.0",
        "sqlalchemy>=1.3.0",
        "alembic>=1.0.0",
        "scapy>=2.4.5",
        "dpkt>=1.9.0",
        "scikit-learn>=0.22.0",
        "numpy>=1.18.0",
        "pandas>=1.0.0",
        "joblib>=0.14.0",
        "schedule>=1.0.0",
        "apscheduler>=3.6.0",
        "paramiko>=2.7.0",
        "reportlab>=3.5.0",
        "email-validator>=1.1.0",
        "prompt-toolkit>=3.0.0",
        "psutil>=5.7.0",
        "cryptography>=3.3.0",
        "requests>=2.24.0",
        "ldap3>=2.7.0",
        "flasgger>=0.9.5",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=3.0.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
            "mypy>=0.910",
        ],
        "mitm": [
            "mitmproxy>=8.0.0",
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
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    zip_safe=False,
)
