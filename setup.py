#! /usr/bin/env python3

import io
from pathlib import Path
from setuptools import setup, find_packages


# 1: clone repo
# 2: build in the same directory as setup.py with python3 -m build
# 3: test install on local pip with python3 -m installer dist/<name_of_pkg_here>.whl


# Loads README.md as long_description
readme_path = Path("README.md")
with io.open(readme_path, "r", encoding="utf-8") as file:
    long_description = file.read()

print(f"=== PACKAGES FOUND: {find_packages()} ===")


setup(
    name="dnswatch",
    version="0.1.0",
    author="Halil Deniz",
    author_email="halildeniz313@gmail.com",
    url="https://www.github.com/HalilDeniz/DNSWatch",
    description="CLI DNS package sniffer & analyzer",
    long_description=long_description,
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
	"requests>=2.0.0",
        "scrapy>=2.4.5",
        "colorama>=0.4.4",
    ],
#    include_package_data=True, #TODO: Include summary package_data into user install path
#    data_files=[("", ["README.md", "SECURITY.md", "LICENSE", "requirements.txt"])],
    entry_points={
        "console_scripts": ["dnswatch = dnswatch.dnswatch:main"],
    },
    keywords=["DNS", "Watcher", "CLI", "UI", "Script", "Program", "Tool", "WiFi", "WLAN", "Packet", "Packets", "Sniffer", "Analyzer"],
 )
 
