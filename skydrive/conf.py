#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function


import itertools as it, operator as op, functools as ft
import os, sys, io, errno, tempfile, fcntl, stat
from os.path import dirname, basename

import logging
log = logging.getLogger(__name__)


class ConfigMixin(object):

	conf_path_default = b'~/.lcrc'
	conf_save = False # if set to some path, state will be written back to it

	# Only keys listed here will be checked and (possibly) added
	conf_keys = dict(
		client={'id', 'secret'},
		auth={'code', 'refresh_token', 'access_expires', 'access_token'} )


	def __init__(self, **kwz):
		raise NotImplementedError('Init should be overidden with something configurable')


	@classmethod
	def from_conf(cls, path=None):
		import yaml

		if path is None:
			path = cls.conf_path_default
			log.debug('Using default state-file path: {}'.format(path))
		path = os.path.expanduser(path)
		with open(path) as src:
			fcntl.lockf(src, fcntl.LOCK_SH)
			conf = yaml.load(src.read())
		conf.setdefault('conf_save', path)

		conf_cls = dict()
		for ns, keys in cls.conf_keys.viewitems():
			for k in keys:
				if conf.get(ns, dict()).get(k) is not None:
					conf_cls['{}_{}'.format(ns, k)] = conf[ns][k]

		self = cls(**conf_cls)
		self.conf_save = conf['conf_save']
		return self


	def sync(self):
		if not self.conf_save: return
		import yaml

		retry = False
		with open(self.conf_save, 'r+') as src:
			fcntl.lockf(src, fcntl.LOCK_SH)
			conf_raw = src.read()
			conf = yaml.load(io.BytesIO(conf_raw)) if conf_raw else dict()

			conf_updated = False
			for ns, keys in self.conf_keys.viewitems():
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
				log.debug('Updating configuration file ({})'.format(src.name))
				with tempfile.NamedTemporaryFile(
						prefix='{}.'.format(basename(self.conf_save)),
						dir=dirname(self.conf_save), delete=False ) as tmp:
					try:
						fcntl.lockf(tmp, fcntl.LOCK_EX)
						yaml.safe_dump(conf, tmp, default_flow_style=False)
						tmp.flush()
						os.fchmod( tmp.fileno(),
							stat.S_IMODE(os.fstat(src.fileno()).st_mode) )

						fcntl.lockf(src, fcntl.LOCK_EX)
						src.seek(0)
						if src.read() != conf_raw: retry = True
						else:
							# Atomic update
							os.rename(tmp.name, src.name)

							# Non-atomic update for pids that already have fd to old file,
							#  but (presumably) are waiting for the write-lock to be released
							src.seek(0), tmp.seek(0)
							src.truncate()
							src.write(tmp.read())
							src.flush()

					finally:
						try: os.unlink(tmp.name)
						except OSError: pass

		if retry:
			log.debug(( 'Configuration file ({}) was changed'
				' during merge, restarting merge' ).format(self.conf_save))
			return self.sync()
