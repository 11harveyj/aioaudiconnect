"""Audi Connect API setup."""

import setuptools
from aioaudiconnect.const import VERSION

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
        "asyncio",
        "aiohttp",
        "async_timeout",
        "bs4",
        "requests",
        "typing"
    ]
)