#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function


import itertools as it, operator as op, functools as ft
from os.path import dirname, exists, isdir, join
import os, sys, yaml

try: from skydrive import api_v5, conf
except ImportError:
	# Make sure it works from a checkout
	if isdir(join(dirname(__file__), 'skydrive'))\
			and exists(join(dirname(__file__), 'setup.py')):
		sys.path.insert(0, dirname(__file__))
		from skydrive import api_v5, conf


def print_result(data):
	yaml.safe_dump(data, sys.stdout, default_flow_style=False)

def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='Tool to manipulate SkyDrive contents.')
	parser.add_argument('-c', '--config',
		metavar='path', default=conf.ConfigMixin.conf_path_default,
		help='Writable configuration state-file (yaml).'
			' Used to store authorization_code, access and refresh tokens.'
			' Should initially contain at least something like "{client: {id: xxx, secret: yyy}}".'
			' Default: %(default)s')
	parser.add_argument('-p', '--path', action='store_true',
		help='Interpret file/folder arguments as human paths, not ids.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')

	cmds = parser.add_subparsers(title='Supported operations')

	cmd = cmds.add_parser('ls', help='List folder contents.')
	cmd.set_defaults(call='ls')
	cmd.add_argument( 'folder',
		nargs='?', default='me/skydrive',
		help='Folder to list contents of (default: %(default)s).' )

	cmd = cmds.add_parser('info', help='Display object metadata.')
	cmd.set_defaults(call='info')
	cmd.add_argument( 'object',
		nargs='?', default='me/skydrive',
		help='Object to get info on (default: %(default)s).' )

	cmd = cmds.add_parser('get', help='Download a file.')
	cmd.set_defaults(call='get')
	cmd = cmds.add_parser('put', help='Upload a file.')
	cmd.set_defaults(call='put')

	optz = parser.parse_args()

	import logging
	log = logging.getLogger()
	logging.basicConfig(level=logging.WARNING
		if not optz.debug else logging.DEBUG)

	api = api_v5.PersistentSkyDriveAPI.from_conf(optz.config)

	if optz.call == 'ls':
		if optz.path: optz.folder = api.get_by_path(optz.folder)
		print_result(api.listdir(optz.folder))

	if optz.call == 'info':
		if optz.path: optz.object = api.get_by_path(optz.object)
		print_result(api.get(optz.object))

	if optz.call == 'get': raise NotImplementedError()
	if optz.call == 'put': raise NotImplementedError()


if __name__ == '__main__': main()
