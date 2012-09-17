#!/usr/bin/env python

from setuptools import setup, find_packages
import os

pkg_root = os.path.dirname(__file__)

# Error-handling here is to allow package to be built w/o README included
try: readme = open(os.path.join(pkg_root, 'README.md')).read()
except IOError: readme = ''

setup(

	name = 'python-skydrive',
	version = '12.09.1',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = 'skydrive api oauth2 rest microsoft cloud live liveconnect',
	url = 'http://github.com/mk-fg/python-skydrive',

	description = 'Python interface to Microsoft LiveConnect SkyDrive REST API',
	long_description = readme,

	classifiers = [
		'Development Status :: 4 - Beta',
		'Intended Audience :: Developers',
		'Intended Audience :: Information Technology',
		'License :: OSI Approved',
		'Operating System :: OS Independent',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Topic :: Internet',
		'Topic :: Software Development',
		'Topic :: System :: Archiving',
		'Topic :: System :: Filesystems' ],

	install_requires = ['requests'],
	extras_require = {'cli': ['PyYAML']},

	packages = find_packages(),
	include_package_data = True,
	# package_data = ... <-- ignored for sdist in some setuptools/distribute versions
	exclude_package_data = {'': ['README.*']},

	entry_points = dict(console_scripts=[
		'skydrive-cli = skydrive.cli_tool:main' ]) )
