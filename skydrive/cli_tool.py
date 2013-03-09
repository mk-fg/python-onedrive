#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import itertools as it, operator as op, functools as ft
from os.path import dirname, exists, isdir, join
from collections import defaultdict
import os, sys, io, re, types, json

try:
    import chardet
except ImportError: # optional
    chardet = None

try:
    from skydrive import api_v5, conf
except ImportError:
    # Make sure it works from a checkout
    if isdir(join(dirname(__file__), 'skydrive')) \
        and exists(join(dirname(__file__), 'setup.py')):
        sys.path.insert(0, dirname(__file__))
        from skydrive import api_v5, conf
    else:
        import api_v5, conf


def tree_node(): return defaultdict(tree_node)

def print_result(data, file=sys.stdout, indent='', indent_level=' '*2):
    if isinstance(data, list):
        for v in data:
            print_result(v, file=file, indent=indent + '- ')
    elif isinstance(data, dict):
        for k, v in sorted(data.viewitems(), key=op.itemgetter(0)):
            print(indent + decode_obj(k, force=True) + ':', file=file, end='')
            if not isinstance(v, (list, dict)): # peek to display simple types inline
                print_result(v, file=file, indent=' ')
            else:
                print(file=file)
                print_result(v, file=file, indent=indent+indent_level)
    else:
        print(indent + decode_obj(data, force=True), file=file)


def size_units(size,
               _units=list(reversed(list((u, 2 ** (i * 10))
                   for i, u in enumerate('BKMGT')))) ):
    for u, u1 in _units:
        if size > u1: break
    return size / float(u1), u


def id_match( s,
              _re_id=re.compile(r'^(file|folder)\.[0-9a-f]{16}\.[0-9A-F]{16}!\d+|folder\.[0-9a-f]{16}$') ):
    return s if _re_id.search(s) else None


def decode_obj(obj, force=False):
    'Convert object to unicode.'
    if isinstance(obj, unicode):
        return obj
    elif isinstance(obj, bytes):
        return obj.decode(chardet.detect(obj)['encoding'])\
            if chardet else obj.decode('utf-8')
    else:
        return obj if not dump else repr(obj)


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
                        help='Interpret file/folder arguments only as human paths, not ids (default: guess).'
                             ' Avoid using such paths if non-unique "name" attributes'
                             ' of objects in the same parent folder might be used.')
    parser.add_argument('-i', '--id', action='store_true',
                        help='Interpret file/folder arguments only as ids (default: guess).')

    parser.add_argument('--debug',
                        action='store_true', help='Verbose operation mode.')

    cmds = parser.add_subparsers(title='Supported operations')

    def add_command(name, **kwz):
        cmd = cmds.add_parser(name, **kwz)
        cmd.set_defaults(call=name)
        return cmd

    cmd = add_command('auth', help='Perform user authentication.')
    cmd.add_argument('url', nargs='?',
                     help='URL with the authorization_code.')

    add_command('quota', help='Print quota information.')
    add_command('recent', help='List recently changed objects.')

    cmd = add_command('info', help='Display object metadata.')
    cmd.add_argument('object',
                     nargs='?', default='me/skydrive',
                     help='Object to get info on (default: %(default)s).')

    cmd = add_command('info_set', help='Manipulate object metadata.')
    cmd.add_argument('object',
                     help='Object to manipulate metadata for.')
    cmd.add_argument('data',
                     help='JSON mapping of values to set'
                          ' (example: {"name": "new_file_name.jpg"}).')

    cmd = add_command('link', help='Get a link to a file.')
    cmd.add_argument('object', help='Object to get link for.')
    cmd.add_argument('-t', '--type', default='shared_read_link',
                     help='Type of link to request. Possible values'
                          ' (default: %(default)s): shared_read_link, embed, shared_edit_link.')

    cmd = add_command('ls', help='List folder contents.')
    cmd.add_argument('-o', '--objects', action='store_true',
                     help='Dump full objects, not just name and id.')
    cmd.add_argument('folder',
                     nargs='?', default='me/skydrive',
                     help='Folder to list contents of (default: %(default)s).')

    cmd = add_command('mkdir', help='Create a folder.')
    cmd.add_argument('name', help='Name of a folder to create.')
    cmd.add_argument('folder',
                     nargs='?', default='me/skydrive',
                     help='Parent folder (default: %(default)s).')
    cmd.add_argument('-m', '--metadata',
                     help='JSON mappings of metadata to set for the created folder.'
                          ' Optonal. Example: {"description": "Photos from last trip to Mordor"}')

    cmd = add_command('get', help='Download file contents.')
    cmd.add_argument('file', help='File (object) to read.')
    cmd.add_argument('file_dst', nargs='?', help='Name/path to save file (object) as.')
    cmd.add_argument('-b', '--byte-range',
                     help='Specific range of bytes to read from a file (default: read all).'
                          ' Should be specified in rfc2616 Range HTTP header format.'
                          ' Examples: 0-499 (start - 499), -500 (end-500 to end).')

    cmd = add_command('put', help='Upload a file.')
    cmd.add_argument('file', help='Path to a local file to upload.')
    cmd.add_argument('folder',
                     nargs='?', default='me/skydrive',
                     help='Folder to put file into (default: %(default)s).')
    cmd.add_argument('-n', '--no-overwrite', action='store_true',
                     help='Do not overwrite existing files with the same "name" attribute (visible name).')

    cmd = add_command('cp', help='Copy file to a folder.')
    cmd.add_argument('file', help='File (object) to copy.')
    cmd.add_argument('folder',
                     nargs='?', default='me/skydrive',
                     help='Folder to copy file to (default: %(default)s).')

    cmd = add_command('mv', help='Move file to a folder.')
    cmd.add_argument('file', help='File (object) to move.')
    cmd.add_argument('folder',
                     nargs='?', default='me/skydrive',
                     help='Folder to move file to (default: %(default)s).')

    cmd = add_command('rm', help='Remove object (file or folder).')
    cmd.add_argument('object', nargs='+', help='Object(s) to remove.')

    cmd = add_command('comments', help='Show comments for a file, object or folder.')
    cmd.add_argument('object', help='Object to show comments for.')

    cmd = add_command('comment_add', help='Add comment for a file, object or folder.')
    cmd.add_argument('object', help='Object to add comment for.')
    cmd.add_argument('message', help='Comment message to add.')

    cmd = add_command('comment_delete', help='Delete comment from a file, object or folder.')
    cmd.add_argument('comment_id',
                     help='ID of the comment to remove (use "comments"'
                          ' action to get comment ids along with the messages).')

    cmd = add_command('tree',
                      help='Show contents of skydrive (or folder) as a tree of file/folder names.'
                           ' Note that this operation will have to (separately) request a listing'
                           ' of every folder under the specified one, so can be quite slow for large'
                           ' number of these.')
    cmd.add_argument('folder',
                     nargs='?', default='me/skydrive',
                     help='Folder to display contents of (default: %(default)s).')

    optz = parser.parse_args()

    if optz.path and optz.id:
        parser.error('--path and --id options cannot be used together.')

    import logging

    log = logging.getLogger()
    logging.basicConfig(level=logging.WARNING
    if not optz.debug else logging.DEBUG)

    api = api_v5.PersistentSkyDriveAPI.from_conf(optz.config)
    res = xres = None
    resolve_path = ( (lambda s: id_match(s) or api.resolve_path(s)) \
                         if not optz.path else api.resolve_path ) if not optz.id else lambda obj_id: obj_id

    # Make best-effort to decode all CLI options to unicode
    for k, v in vars(optz).viewitems():
        if isinstance(v, bytes):
            setattr(optz, k, decode_obj(v))
        elif isinstance(v, list):
            setattr(optz, k, map(decode_obj, v))

    if optz.call == 'auth':
        if not optz.url:
            print('Visit the following URL in any web browser (firefox, chrome, safari, etc),\n'
                  '  authorize there, confirm access permissions, and paste URL of an empty page\n'
                  '  (starting with "https://login.live.com/oauth20_desktop.srf")'
                  ' you will get redirected to in the end.')
            print('Alternatively, use the returned (after redirects)'
                  ' URL with "{} auth <URL>" command.\n'.format(sys.argv[0]))
            print('URL to visit: {}\n'.format(api.auth_user_get_url()))
            optz.url = raw_input('URL after last redirect: ').strip()
        if optz.url:
            api.auth_user_process_url(optz.url)
            api.auth_get_token()
            print('API authorization was completed successfully.')

    elif optz.call == 'quota':
        df, ds = map(size_units, api.get_quota())
        res = dict(free='{:.1f}{}'.format(*df), quota='{:.1f}{}'.format(*ds))
    elif optz.call == 'recent':
        res = api('me/skydrive/recent_docs')['data']

    elif optz.call == 'ls':
        res = list(api.listdir(resolve_path(optz.folder)))
        if not optz.objects: res = map(op.itemgetter('name'), res)

    elif optz.call == 'info':
        res = api.info(resolve_path(optz.object))
    elif optz.call == 'info_set':
        xres = api.info_update(
            resolve_path(optz.object), json.loads(optz.data))
    elif optz.call == 'link':
        res = api.link(resolve_path(optz.object), optz.type)
    elif optz.call == 'comments':
        res = api.comments(resolve_path(optz.object))
    elif optz.call == 'comment_add':
        res = api.comment_add(resolve_path(optz.object), optz.message)
    elif optz.call == 'comment_delete':
        res = api.comment_delete(optz.comment_id)

    elif optz.call == 'mkdir':
        xres = api.mkdir(name=optz.name, folder_id=resolve_path(optz.folder),
                         metadata=optz.metadata and json.loads(optz.metadata) or dict())

    elif optz.call == 'get':
        contents = api.get(resolve_path(optz.file), byte_range=optz.byte_range)
        if optz.file_dst:
            dst_dir = os.path.dirname(os.path.abspath(optz.file_dst))
            if not os.path.isdir(dst_dir):
                os.makedirs(dst_dir)
            with open(optz.file_dst, "wb") as dst:
                dst.write(contents)
        else:
            sys.stdout.write(contents)
            sys.stdout.flush()

    elif optz.call == 'put':
        xres = api.put(optz.file,
                       resolve_path(optz.folder), overwrite=not optz.no_overwrite)

    elif optz.call in ['cp', 'mv']:
        argz = map(resolve_path, [optz.file, optz.folder])
        xres = (api.move if optz.call == 'mv' else api.copy)(*argz)

    elif optz.call == 'rm':
        for obj in it.imap(resolve_path, optz.object): xres = api.delete(obj)


    elif optz.call == 'tree':

        def recurse(obj_id):
            node = tree_node()
            for obj in api.listdir(obj_id):
                node[obj['name']] = recurse(obj['id']) \
                    if obj['type'] in ['folder', 'album'] else obj['type']
            return node

        root_id = resolve_path(optz.folder)
        res = {api.info(root_id)['name']: recurse(root_id)}


    else:
        parser.error('Unrecognized command: {}'.format(optz.call))

    if res is not None: print_result(res)
    if optz.debug and xres is not None:
        buff = io.BytesIO()
        print_result(xres, file=buff)
        log.debug('Call result:\n{0}\n{1}{0}'.format('-' * 20, buff.getvalue()))


if __name__ == '__main__': main()
