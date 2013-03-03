#!/usr/bin/env python

from setuptools import setup, find_packages
import os

pkg_root = os.path.dirname(__file__)

# Error-handling here is to allow package to be built w/o README included
try:
    readme = open(os.path.join(pkg_root, 'README.txt')).read()
except IOError:
    readme = ''

setup(

    name='python-skydrive',
    version='13.01.2',
    author='Mike Kazantsev',
    author_email='mk.fraggod@gmail.com',
    license='WTFPL',
    keywords='skydrive api oauth2 rest microsoft cloud live liveconnect',
    url='http://github.com/mk-fg/python-skydrive',

    description='Python and command-line interface'
                ' for Microsoft LiveConnect SkyDrive REST API v5.0',
    long_description=readme,

    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Internet',
        'Topic :: Software Development',
        'Topic :: System :: Archiving',
        'Topic :: System :: Filesystems',
        'Topic :: Utilities'],

    # install_requires = [],
    extras_require=dict(
        standalone=['requests'],
        cli=['PyYAML', 'requests', 'chardet'],
        conf=['PyYAML', 'requests', 'chardet']),

    packages=find_packages(),
    include_package_data=True,
    package_data={'': ['README.txt']},
    exclude_package_data={'': ['README.*']},

    entry_points=dict(console_scripts=[
        'skydrive-cli = skydrive.cli_tool:main']))
