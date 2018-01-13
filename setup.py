#!/usr/bin/env python
from setuptools import setup, find_packages


setup(
    name='bpf-tools',
    version='1.0',
    description='Working with BPF programs',
    license='MIT',

    install_requires=['pyparsing'],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    entry_points={
        'console_scripts': ['bpf = bpftools.cli:main']
    }
)