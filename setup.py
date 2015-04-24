#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='simpybtc',
      version='1.1.27',
      description='Python Bitcoin Tools',
      author='Vitalik Buterin',
      author_email='vbuterin@gmail.com',
      url='http://github.com/simcity4242/simpybtc',
      packages=['simpybtc'],
      scripts=['pybtctool'],
      include_package_data=True,
      data_files=[("", ["LICENSE"])],
      )
