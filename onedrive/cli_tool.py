#!/usr/bin/env python2
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import itertools as it, operator as op, functools as ft
from os.path import dirname, basename, exists, isdir, join, abspath
from posixpath import join as ujoin, dirname as udirname, basename as ubasename
from collections import defaultdict
import os, sys, io, logging, re, types, json

try: import chardet
except ImportError: chardet = None # completely optional

try: import onedrive
except ImportError:
	# Make sure tool works from a checkout
	if __name__ != '__main__': raise
	pkg_root = abspath(dirname(__file__))
	for pkg_root in pkg_root, dirname(pkg_root):
		if isdir(join(pkg_root, 'onedrive'))\
				and exists(join(pkg_root, 'setup.py')):
			sys.path.insert(0, dirname(__file__))
			try: import onedrive
			except ImportError: pass
			else: break
	else: raise ImportError('Failed to find/import "onedrive" module')
from onedrive import api_v5, conf


force_encoding = None

def tree_node(): return defaultdict(tree_node)

def print_result(data, file, tpl=None, indent='', indent_first=None, indent_level=' '*2):
	# Custom printer is used because pyyaml isn't very pretty with unicode
	if isinstance(data, list):
		for v in data:
			print_result( v, file=file, tpl=tpl, indent=indent + '  ',
				indent_first=(indent_first if indent_first is not None else indent) + '- ' )
			indent_first = None
	elif isinstance(data, dict):
		indent_cur = indent_first if indent_first is not None else indent
		if tpl is None:
			for k, v in sorted(data.viewitems(), key=op.itemgetter(0)):
				print(indent_cur + decode_obj(k, force=True) + ':', file=file, end='')
				indent_cur = indent
				if not isinstance(v, (list, dict)): # peek to display simple types inline
					print_result(v, file=file, tpl=tpl, indent=' ')
				else:
					print('', file=file)
					print_result(v, file=file, tpl=tpl, indent=indent_cur+indent_level)
		else:
			if '{' not in tpl and not re.search(r'^\s*$', tpl): tpl = '{{0[{}]}}'.format(tpl)
			try: data = tpl.format(data)
			except Exception as err:
				log.debug( 'Omitting object that does not match template'
					' (%r) from output (error: %s %s): %r', tpl, type(err), err, data )
			else: print_result(data, file=file, indent=indent_cur)
	else:
		if indent_first is not None: indent = indent_first
		print(indent + decode_obj(data, force=True), file=file)

def decode_obj(obj, force=False):
	'Convert or dump object to unicode.'
	if isinstance(obj, unicode): return obj
	elif isinstance(obj, bytes):
		if force_encoding is not None: return obj.decode(force_encoding)
		if chardet:
			enc_guess = chardet.detect(obj)
			if enc_guess['confidence'] > 0.7:
				return obj.decode(enc_guess['encoding'])
		return obj.decode('utf-8')
	else:
		return obj if not force else repr(obj)

def size_units( size,
		_units=list(reversed(list((u, 2 ** (i * 10)) for i, u in enumerate('BKMGT')))) ):
	for u, u1 in _units:
		if size > u1: break
	return size / float(u1), u

def id_match(s, _re_id=re.compile(
		r'^('
			r'(file|folder)\.[0-9a-f]{16}\.[0-9A-F]{16}!\d+|folder\.[0-9a-f]{16}'
			# Force-resolving all "special-looking" paths here, because
			#  there are separate commands (e.g. "quota") to get data from these
			# r'|me(/\w+(/.*)?)?' # special paths like "me/skydrive"
		r')$' ) ):
	return s if s and _re_id.search(s) else None


def main():
	import argparse

	parser = argparse.ArgumentParser(
		description='Tool to manipulate OneDrive contents.')
	parser.add_argument('-c', '--config',
		metavar='path', default=conf.ConfigMixin.conf_path_default,
		help='Writable configuration state-file (yaml).'
			' Used to store authorization_code, access and refresh tokens.'
			' Should initially contain at least something like "{client: {id: xxx, secret: yyy}}".'
			' Default: %(default)s')

	parser.add_argument('-p', '--path', action='store_true',
		help='Interpret file/folder arguments only as human paths, not ids (default: guess).'
			' Avoid using such paths if non-unique "name"'
				' attributes of objects in the same parent folder might be used.')
	parser.add_argument('-i', '--id', action='store_true',
		help='Interpret file/folder arguments only as ids (default: guess).')

	parser.add_argument('-k', '--object-key', metavar='spec',
		help='If returned data is an object, or a list of objects, only print this key from there.'
			' Supplied spec can be a template string for python str.format,'
				' assuming that object gets passed as the first argument.'
			' Objects that do not have specified key or cannot'
				' be formatted using supplied template will be ignored entirely.'
			' Example: {0[id]} {0[name]!r} {0[count]:03d} (uploader: {0[from][name]})')

	parser.add_argument('-e', '--encoding', metavar='enc', default='utf-8',
		help='Use specified encoding (example: utf-8) for CLI input/output.'
			' See full list of supported encodings at:'
				' http://docs.python.org/2/library/codecs.html#standard-encodings .'
			' Pass empty string or "detect" to detect input encoding via'
				' chardet module, if available, falling back to utf-8 and terminal encoding for output.'
			' Forced utf-8 is used by default, for consistency and due to its ubiquity.')

	parser.add_argument('-V', '--version', action='version',
		version='python-onedrive {}'.format(onedrive.__version__),
		help='Print version number and exit.')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')

	cmds = parser.add_subparsers(title='Supported operations', dest='call')

	cmd = cmds.add_parser('auth', help='Perform user authentication.')
	cmd.add_argument('url', nargs='?', help='URL with the authorization_code.')

	cmds.add_parser('auth_refresh',
		help='Force-refresh OAuth2 access_token.'
			' Should never be necessary under normal conditions.')

	cmds.add_parser('quota', help='Print quota information.')
	cmds.add_parser('user', help='Print user data.')
	cmds.add_parser('recent', help='List recently changed objects.')

	cmd = cmds.add_parser('info', help='Display object metadata.')
	cmd.add_argument('object',
		nargs='?', default='me/skydrive',
		help='Object to get info on (default: %(default)s).')

	cmd = cmds.add_parser('info_set', help='Manipulate object metadata.')
	cmd.add_argument('object', help='Object to manipulate metadata for.')
	cmd.add_argument('data',
		help='JSON mapping of values to set (example: {"name": "new_file_name.jpg"}).')

	cmd = cmds.add_parser('link', help='Get a link to a file.')
	cmd.add_argument('object', help='Object to get link for.')
	cmd.add_argument('-t', '--type', default='shared_read_link',
		help='Type of link to request. Possible values'
			' (default: %(default)s): shared_read_link, embed, shared_edit_link.')

	cmd = cmds.add_parser('ls', help='List folder contents.')
	cmd.add_argument('folder',
		nargs='?', default='me/skydrive',
		help='Folder to list contents of (default: %(default)s).')
	cmd.add_argument('-r', '--range',
		metavar='{[offset]-[limit] | limit}',
		help='List only specified range of objects inside.'
			' Can be either dash-separated "offset-limit" tuple'
				' (any of these can be omitted) or a single "limit" number.')
	cmd.add_argument('-o', '--objects', action='store_true',
		help='Dump full objects, not just name and id.')

	cmd = cmds.add_parser('mkdir', help='Create a folder.')
	cmd.add_argument('name',
		help='Name (or a path consisting of dirname + basename) of a folder to create.')
	cmd.add_argument('folder',
		nargs='?', default=None,
		help='Parent folder (default: me/skydrive).')
	cmd.add_argument('-m', '--metadata',
		help='JSON mappings of metadata to set for the created folder.'
			' Optonal. Example: {"description": "Photos from last trip to Mordor"}')

	cmd = cmds.add_parser('get', help='Download file contents.')
	cmd.add_argument('file', help='File (object) to read.')
	cmd.add_argument('file_dst', nargs='?', help='Name/path to save file (object) as.')
	cmd.add_argument('-b', '--byte-range',
		help='Specific range of bytes to read from a file (default: read all).'
			' Should be specified in rfc2616 Range HTTP header format.'
			' Examples: 0-499 (start - 499), -500 (end-500 to end).')

	cmd = cmds.add_parser('put', help='Upload a file.')
	cmd.add_argument('file', help='Path to a local file to upload.')
	cmd.add_argument('folder',
		nargs='?', default='me/skydrive',
		help='Folder to put file into (default: %(default)s).')
	cmd.add_argument('-n', '--no-overwrite', action='store_true', default=None,
		help='Do not overwrite existing files with the same "name" attribute (visible name).'
			' Default (and documented) API behavior is to overwrite such files.')
	cmd.add_argument('-d', '--no-downsize', action='store_true', default=None,
		help='Disable automatic downsizing when uploading a large image.'
			' Default (and documented) API behavior is to downsize images.')
	cmd.add_argument('-b', '--bits', action='store_true',
		help='Force usage of BITS API (uploads via multiple http requests).'
			' Default is to only fallback to it for large (wrt API limits) files.')
	cmd.add_argument('--bits-frag-bytes',
		type=int, metavar='number',
		default=api_v5.PersistentOneDriveAPI.api_bits_default_frag_bytes,
		help='Fragment size for using BITS API (if used), in bytes. Default: %(default)s')
	cmd.add_argument('--bits-do-auth-refresh-before-commit-hack', action='store_true',
		help='Do auth_refresh trick before upload session commit request.'
			' This is reported to avoid current (as of 2015-01-16) http 5XX errors from the API.'
			' See github issue #39, gist with BITS API spec and the README file for more details.')

	cmd = cmds.add_parser('cp', help='Copy file to a folder.')
	cmd.add_argument('file', help='File (object) to copy.')
	cmd.add_argument('folder',
		nargs='?', default='me/skydrive',
		help='Folder to copy file to (default: %(default)s).')

	cmd = cmds.add_parser('mv', help='Move file to a folder.')
	cmd.add_argument('file', help='File (object) to move.')
	cmd.add_argument('folder',
		nargs='?', default='me/skydrive',
		help='Folder to move file to (default: %(default)s).')

	cmd = cmds.add_parser('rm', help='Remove object (file or folder).')
	cmd.add_argument('object', nargs='+', help='Object(s) to remove.')

	cmd = cmds.add_parser('comments', help='Show comments for a file, object or folder.')
	cmd.add_argument('object', help='Object to show comments for.')

	cmd = cmds.add_parser('comment_add', help='Add comment for a file, object or folder.')
	cmd.add_argument('object', help='Object to add comment for.')
	cmd.add_argument('message', help='Comment message to add.')

	cmd = cmds.add_parser('comment_delete', help='Delete comment from a file, object or folder.')
	cmd.add_argument('comment_id',
		help='ID of the comment to remove (use "comments"'
			' action to get comment ids along with the messages).')

	cmd = cmds.add_parser('tree',
		help='Show contents of onedrive (or folder) as a tree of file/folder names.'
			' Note that this operation will have to (separately) request a listing of every'
				' folder under the specified one, so can be quite slow for large number of these.')
	cmd.add_argument('folder',
		nargs='?', default='me/skydrive',
		help='Folder to display contents of (default: %(default)s).')
	cmd.add_argument('-o', '--objects', action='store_true',
		help='Dump full objects, not just name and type.')

	optz = parser.parse_args()

	if optz.path and optz.id:
		parser.error('--path and --id options cannot be used together.')

	if optz.encoding.strip('"') in [None, '', 'detect']: optz.encoding = None
	if optz.encoding:
		global force_encoding
		force_encoding = optz.encoding
		reload(sys)
		sys.setdefaultencoding(force_encoding)

	global log
	log = logging.getLogger()
	logging.basicConfig(level=logging.WARNING
	if not optz.debug else logging.DEBUG)

	api = api_v5.PersistentOneDriveAPI.from_conf(optz.config)
	res = xres = None
	resolve_path = ( (lambda s: id_match(s) or api.resolve_path(s))\
		if not optz.path else api.resolve_path ) if not optz.id else (lambda obj_id: obj_id)

	# Make best-effort to decode all CLI options to unicode
	for k, v in vars(optz).viewitems():
		if isinstance(v, bytes): setattr(optz, k, decode_obj(v))
		elif isinstance(v, list): setattr(optz, k, map(decode_obj, v))

	if optz.call == 'auth':
		if not optz.url:
			print(
				'Visit the following URL in any web browser (firefox, chrome, safari, etc),\n'
				'  authorize there, confirm access permissions, and paste URL of an empty page\n'
				'  (starting with "https://login.live.com/oauth20_desktop.srf")'
					' you will get redirected to in the end.' )
			print(
				'Alternatively, use the returned (after redirects)'
				' URL with "{} auth <URL>" command.\n'.format(sys.argv[0]) )
			print('URL to visit: {}\n'.format(api.auth_user_get_url()))
			try: import readline # for better compatibility with terminal quirks, see #40
			except ImportError: pass
			optz.url = raw_input('URL after last redirect: ').strip()
		if optz.url:
			api.auth_user_process_url(optz.url)
			api.auth_get_token()
			print('API authorization was completed successfully.')

	elif optz.call == 'auth_refresh':
		xres = dict(scope_granted=api.auth_get_token())

	elif optz.call == 'quota':
		df, ds = map(size_units, api.get_quota())
		res = dict(free='{:.1f}{}'.format(*df), quota='{:.1f}{}'.format(*ds))
	elif optz.call == 'user':
		res = api.get_user_data()
	elif optz.call == 'recent':
		res = api('me/skydrive/recent_docs')['data']

	elif optz.call == 'ls':
		offset = limit = None
		if optz.range:
			span = re.search(r'^(\d+)?[-:](\d+)?$', optz.range)
			try:
				if not span: limit = int(optz.range)
				else: offset, limit = map(int, span.groups())
			except ValueError:
				parser.error(
					'--range argument must be in the "[offset]-[limit]"'
						' or just "limit" format, with integers as both offset and'
						' limit (if not omitted). Provided: {}'.format(optz.range) )
		res = sorted(
			api.listdir(resolve_path(optz.folder), offset=offset, limit=limit),
			key=op.itemgetter('name') )
		if not optz.objects: res = map(op.itemgetter('name'), res)

	elif optz.call == 'info':
		res = api.info(resolve_path(optz.object))
	elif optz.call == 'info_set':
		xres = api.info_update(resolve_path(optz.object), json.loads(optz.data))
	elif optz.call == 'link':
		res = api.link(resolve_path(optz.object), optz.type)
	elif optz.call == 'comments':
		res = api.comments(resolve_path(optz.object))
	elif optz.call == 'comment_add':
		res = api.comment_add(resolve_path(optz.object), optz.message)
	elif optz.call == 'comment_delete':
		res = api.comment_delete(optz.comment_id)

	elif optz.call == 'mkdir':
		name, path = optz.name.replace('\\', '/'), optz.folder
		if '/' in name:
			name, path_ext = ubasename(name), udirname(name)
			path = ujoin(path, path_ext.strip('/')) if path else path_ext
		xres = api.mkdir( name=name, folder_id=resolve_path(path),
			metadata=optz.metadata and json.loads(optz.metadata) or dict() )

	elif optz.call == 'get':
		contents = api.get(resolve_path(optz.file), byte_range=optz.byte_range)
		if optz.file_dst:
			dst_dir = dirname(abspath(optz.file_dst))
			if not isdir(dst_dir): os.makedirs(dst_dir)
			with open(optz.file_dst, "wb") as dst: dst.write(contents)
		else:
			sys.stdout.write(contents)
			sys.stdout.flush()

	elif optz.call == 'put':
		dst = optz.folder
		if optz.bits_do_auth_refresh_before_commit_hack:
			api.api_bits_auth_refresh_before_commit_hack = True
		if optz.bits_frag_bytes > 0: api.api_bits_default_frag_bytes = optz.bits_frag_bytes
		if dst is not None:
			xres = api.put( optz.file, resolve_path(dst),
				bits_api_fallback=0 if optz.bits else True, # 0 = "always use BITS"
				overwrite=optz.no_overwrite and False, downsize=optz.no_downsize and False )

	elif optz.call in ['cp', 'mv']:
		argz = map(resolve_path, [optz.file, optz.folder])
		xres = (api.move if optz.call == 'mv' else api.copy)(*argz)

	elif optz.call == 'rm':
		for obj in it.imap(resolve_path, optz.object): xres = api.delete(obj)

	elif optz.call == 'tree':
		def recurse(obj_id):
			node = tree_node()
			for obj in api.listdir(obj_id):
				# Make sure to dump files as lists with -o,
				#  not dicts, to make them distinguishable from dirs
				res = obj['type'] if not optz.objects else [obj['type'], obj]
				node[obj['name']] = recurse(obj['id']) \
					if obj['type'] in ['folder', 'album'] else res
			return node
		root_id = resolve_path(optz.folder)
		res = {api.info(root_id)['name']: recurse(root_id)}

	else:
		parser.error('Unrecognized command: {}'.format(optz.call))

	if res is not None: print_result(res, tpl=optz.object_key, file=sys.stdout)
	if optz.debug and xres is not None:
		buff = io.StringIO()
		print_result(xres, file=buff)
		log.debug('Call result:\n{0}\n{1}{0}'.format('-' * 20, buff.getvalue()))


if __name__ == '__main__': main()
