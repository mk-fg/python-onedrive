#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import itertools as it, operator as op, functools as ft
import os, sys, io, errno, tempfile, stat, re
from os.path import dirname, basename

import logging

log = logging.getLogger(__name__)


class ConfigMixin(object):

	#: Path to configuration file to use in from_conf() by default.
	conf_path_default = b'~/.lcrc'

	#: If set to some path, updates will be written back to it.
	conf_save = False

	#: Raise human-readable errors on structure issues,
	#:  which assume that there is an user-accessible configuration file
	conf_raise_structure_errors = False

	#: Hierarchical list of keys to write back
	#:  to configuration file (preserving the rest) on updates.
	conf_update_keys = dict(
		client={'id', 'secret'},
		auth={'code', 'refresh_token', 'access_expires', 'access_token'},
		request={'extra_keywords', 'adapter_settings', 'base_headers'} )

	def __init__(self, **kwz):
		raise NotImplementedError('Init should be overidden with something configurable')

	@classmethod
	def from_conf(cls, path=None, **overrides):
		'''Initialize instance from YAML configuration file,
			writing updates (only to keys, specified by "conf_update_keys") back to it.'''
		from onedrive import portalocker
		import yaml

		if path is None:
			path = cls.conf_path_default
			log.debug('Using default state-file path: %r', path)
		path = os.path.expanduser(path)
		with open(path, 'rb') as src:
			portalocker.lock(src, portalocker.LOCK_SH)
			yaml_str = src.read()
			portalocker.unlock(src)
		conf = yaml.safe_load(yaml_str)
		conf.setdefault('conf_save', path)

		conf_cls = dict()
		for ns, keys in cls.conf_update_keys.viewitems():
			for k in keys:
				try:
					v = conf.get(ns, dict()).get(k)
				except AttributeError:
					if not cls.conf_raise_structure_errors: raise
					raise KeyError((
						'Unable to get value for configuration parameter'
							' "{k}" in section "{ns}", check configuration file (path: {path}) syntax'
							' near the aforementioned section/value.' ).format(ns=ns, k=k, path=path))
				if v is not None: conf_cls['{}_{}'.format(ns, k)] = conf[ns][k]
		conf_cls.update(overrides)

		# Hack to work around YAML parsing client_id of e.g. 000123 as an octal int
		if isinstance(conf.get('client', dict()).get('id'), (int, long)):
			log.warn( 'Detected client_id being parsed as an integer (as per yaml), trying to un-mangle it.'
				' If requests will still fail afterwards, please replace it in the configuration file (path: %r),'
					' also putting single or double quotes (either one should work) around the value.', path )
			cid = conf['client']['id']
			if not re.search(r'\b(0*)?{:d}\b'.format(cid), yaml_str)\
					and re.search(r'\b(0*)?{:o}\b'.format(cid), yaml_str):
				cid = int('{:0}'.format(cid))
			conf['client']['id'] = '{:016d}'.format(cid)

		self = cls(**conf_cls)
		self.conf_save = conf['conf_save']
		return self

	def sync(self):
		if not self.conf_save: return
		from onedrive import portalocker
		import yaml

		retry = False
		with open(self.conf_save, 'r+b') as src:
			portalocker.lock(src, portalocker.LOCK_SH)
			conf_raw = src.read()
			conf = yaml.safe_load(io.BytesIO(conf_raw)) if conf_raw else dict()
			portalocker.unlock(src)

			conf_updated = False
			for ns, keys in self.conf_update_keys.viewitems():
				for k in keys:
					v = getattr(self, '{}_{}'.format(ns, k), None)
					if isinstance(v, unicode): v = v.encode('utf-8')
					if v != conf.get(ns, dict()).get(k):
						# log.debug(
						# 	'Different val ({}.{}): {!r} != {!r}'\
						# 	.format(ns, k, v, conf.get(ns, dict()).get(k)) )
						conf.setdefault(ns, dict())[k] = v
						conf_updated = True

			if conf_updated:
				log.debug('Updating configuration file (%r)', src.name)
				conf_new = yaml.safe_dump(conf, default_flow_style=False)
				if os.name == 'nt':
					# lockf + tempfile + rename doesn't work on windows due to
					#  "[Error 32] ... being used by another process",
					#  so this update can potentially leave broken file there
					# Should probably be fixed by someone who uses/knows about windows
					portalocker.lock(src, portalocker.LOCK_EX)
					src.seek(0)
					if src.read() != conf_raw: retry = True
					else:
						src.seek(0)
						src.truncate()
						src.write(conf_new)
						src.flush()
						portalocker.unlock(src)

				else:
					with tempfile.NamedTemporaryFile(
							prefix='{}.'.format(basename(self.conf_save)),
							dir=dirname(self.conf_save), delete=False) as tmp:
						try:
							portalocker.lock(src, portalocker.LOCK_EX)
							src.seek(0)
							if src.read() != conf_raw: retry = True
							else:
								portalocker.lock(tmp, portalocker.LOCK_EX)
								tmp.write(conf_new)
								os.fchmod(tmp.fileno(), stat.S_IMODE(os.fstat(src.fileno()).st_mode))
								os.rename(tmp.name, src.name)
								# Non-atomic update for pids that already have fd to old file,
								#  but (presumably) are waiting for the write-lock to be released
								src.seek(0)
								src.truncate()
								src.write(conf_new)
						finally:
							try: os.unlink(tmp.name)
							except OSError: pass

		if retry:
			log.debug(
				'Configuration file (%r) was changed'
					' during merge, restarting merge', self.conf_save )
			return self.sync()
