#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='btc',
      version='2.0.01',
      description='Python Bitcoin Tools',
      author='Vitalik Buterin',
      author_email='vbuterin@gmail.com',
      url='http://github.com/simcity4242/simpybtc',
      packages=['btc'],
      scripts=['btc'],
      include_package_data=True,
      data_files=[("", ["LICENSE"])],
      )
