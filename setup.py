from setuptools import setup, find_packages

setup(
    name="secploy",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "pyyaml>=5.1",
        "pydantic>=2.0.0",
        "websocket-client>=1.9.0",
        "psutil>=5.4.0",
        "gputil>=1.4.0; extra == 'realtime'",
    ],
    extras_require={
        "realtime": ["websocket-client>=1.9.0", "gputil>=1.4.0"],
    },
    author="Agastronics",
    author_email="support@secploy.com",
    description="Event ingestion, log capture, realtime config sync, and security gating SDK for Python applications",
    long_description=open("README.md").read() if open("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/agastronics/secploy-python-sdk",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    entry_points={
        "console_scripts": [
            "secploy=secploy:cli",
        ],
    },
)
