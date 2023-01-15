"""Audi Connect API setup."""

import setuptools
from aioaudiconnect.audi_connect import VERSION

with open("README.md", "r", encoding="utf8", errors="surrogateescape") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aioaudiconnect",
    version=VERSION,
    author="11harveyj",
    author_email="jordan@hrvy.uk",
    description="A Python Library that exposes Audi Connect services via a generic API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/11harveyj/aioaudiconnect",
    packages=setuptools.find_packages(),
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Topic :: Home Automation",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="audi audiconnect car carconnect connect",
    python_requires=">=3.6",
    install_requires=[
        "json",
        "asyncio",
        "aiohttp",
        "async_timeout",
        "datetime",
        "bs4",
        "requests",
        "urllib",
        "abc",
        "uuid",
        "base64",
        "os",
        "math",
        "re",
        "logging",
        "time",
        "haslib",
        "hmac",
        "typing"
    ]
)