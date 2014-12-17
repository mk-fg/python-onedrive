#!/usr/bin/env python

from setuptools import setup, find_packages
import os, runpy

pkg_root = os.path.dirname(__file__)
__version__ = runpy.run_path(
	os.path.join(pkg_root, 'onedrive', '__init__.py') )['__version__']

# Error-handling here is to allow package to be built w/o README included
try: readme = open(os.path.join(pkg_root, 'README.txt')).read()
except IOError: readme = ''

setup(

	name='python-onedrive',
	version=__version__,
	author='Mike Kazantsev, Antonio Chen',
	author_email='mk.fraggod@gmail.com',
	license='WTFPL',
	keywords=[ 'onedrive', 'skydrive', 'api', 'oauth2',
		'rest', 'microsoft', 'cloud', 'live', 'liveconnect',
		'json', 'storage', 'storage provider', 'file hosting' ],

	url='http://github.com/mk-fg/python-onedrive',

	description='Python and command-line interface'
				' for Microsoft LiveConnect OneDrive REST API v5.0',
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
		cli=['PyYAML', 'requests'],
		conf=['PyYAML', 'requests']),

	packages=find_packages(),
	include_package_data=True,
	package_data={'': ['README.txt']},
	exclude_package_data={'': ['README.*']},

	entry_points=dict(console_scripts=[
		'onedrive-cli = onedrive.cli_tool:main']))
