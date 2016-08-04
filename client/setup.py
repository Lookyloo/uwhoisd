#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup


setup(
    name='uwhois',
    version='0.5',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/Rafiot/uwhoisd',
    description='Python API for Uwhoisd.',
    packages=['uwhois'],
    scripts=['bin/uwhois'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
    ],
)
