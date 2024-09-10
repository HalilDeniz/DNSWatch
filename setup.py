from setuptools import setup, find_packages

setup(
    name='dnswatch',
    version='2.1.0',
    packages=find_packages(),
    install_requires=[
        'requests',
        'scapy',
        'colorama',
        'datetime',
    ],
    entry_points={
        'console_scripts': [
            'dnswatch = dnswatch.dnswatch:main',
        ],
    },
    author='Halil Ibrahim Deniz',
    long_description=open('README.md').read(),
    author_email='halildeniz313@gmail.com',
    description='DNS sniffer tool',
    license='MIT',
    keywords='dns sniffer cybersecurity',
    url='https://github.com/HalilDeniz/DNSWatch',

    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
