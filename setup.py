#!/usr/bin/env python

from __future__ import with_statement

import os.path

from setuptools import setup, find_packages


def read(filename: str) -> str:
    """Read files relative to this file."""
    full_path = os.path.join(os.path.dirname(__file__), filename)
    with open(full_path, 'r') as fh:
        return fh.read()


setup(
    name='uwhoisd',
    version='0.0.7',
    description="Universal domain WHOIS proxy server.",
    long_description=read('README.md') + "\n\n" + read("ChangeLog"),
    url='https://github.com/kgaughan/uwhoisd/',
    license='MIT',
    packages=find_packages(exclude=['tests']),
    zip_safe=True,

    setup_requires=[
        'setuptools',
        'wheel',
    ],
    install_requires=[
        'tornado',
        'redis>=3'
    ],

    entry_points={
        'console_scripts': (
            'uwhoisd = uwhoisd:main',
        ),
    },

    scripts=['bin/run_backend.py', 'bin/start.py'],

    classifiers=(  # type: ignore[arg-type]
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: System :: Networking',
    ),

    author='Keith Gaughan',
    author_email='k@stereochro.me',
)
