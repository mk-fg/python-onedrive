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

def size_units( size,
		_units = list(reversed(list( (u,2**(i*10))
			for i,u in enumerate('BKMGT') ))) ):
	for u,u1 in _units:
		if size > u1: break
	return size / float(u1), u

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
		help='Try to interpret file/folder arguments as human paths as well.')
	parser.add_argument('--path-only', action='store_true',
		help='Interpret file/folder arguments only as human paths, not ids. Overrides --path.')

	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')

	cmds = parser.add_subparsers(title='Supported operations')

	cmd = cmds.add_parser('quota', help='Print quota information.')
	cmd.set_defaults(call='quota')

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

	cmd = cmds.add_parser('cp', help='Copy file to a folder.')
	cmd.set_defaults(call='cp')
	cmd.add_argument('file', help='File (object) to copy.')
	cmd.add_argument( 'folder',
		nargs='?', default='me/skydrive',
		help='Folder to copy file to (default: %(default)s).' )
	cmd = cmds.add_parser('mv', help='Move file to a folder.')
	cmd.set_defaults(call='mv')
	cmd.add_argument('file', help='File (object) to move.')
	cmd.add_argument( 'folder',
		nargs='?', default='me/skydrive',
		help='Folder to move file to (default: %(default)s).' )

	cmd = cmds.add_parser('rm', help='Remove object (file or folder).')
	cmd.set_defaults(call='rm')
	cmd.add_argument('object', help='Object to remove.')

	optz = parser.parse_args()
	if optz.path_only: optz.path = True

	import logging
	log = logging.getLogger()
	logging.basicConfig(level=logging.WARNING
		if not optz.debug else logging.DEBUG)

	api = api_v5.PersistentSkyDriveAPI.from_conf(optz.config)
	res = None
	resolve_path = ft.partial(
			api.resolve_path, id_fallback=not optz.path_only )\
		if optz.path else lambda path: path

	if optz.call == 'quota':
		df, ds = map(size_units, api.get_quota())
		res = dict(free='{:.1f}{}'.format(*df), quota='{:.1f}{}'.format(*ds))

	elif optz.call == 'ls': res = api.listdir(resolve_path(optz.folder))
	elif optz.call == 'info': res = api.info(resolve_path(optz.object))

	elif optz.call == 'get': raise NotImplementedError()
	elif optz.call == 'put': raise NotImplementedError()

	elif optz.call in ['cp', 'mv']:
		argz = map(resolve_path, [optz.file, optz.folder])
		(api.move if optz.call == 'mv' else api.copy)(*argz)

	elif optz.call == 'rm': api.delete(resolve_path(optz.object))

	else: parser.error('Unrecognized command: {}'.format(optz.call))

	if res is not None: print_result(res)


if __name__ == '__main__': main()
