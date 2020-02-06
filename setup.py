# -*- coding: utf-8 -*-

# Learn more: https://github.com/kennethreitz/setup.py

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='python-mstk',
    version='0.1.0',
    description='Module to support Maker Space Tool Kit python programs',
    long_description=readme,
    author='Peter Hartmann',
    author_email='peter@hartmanncomputer.com',
    url='https://github.com/makerspacetoolkit/python-mstk',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)

