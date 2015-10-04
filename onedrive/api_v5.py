#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import itertools as it, operator as op, functools as ft

from datetime import datetime, timedelta
from posixpath import join as ujoin # used for url pahs
from os.path import join, basename, dirname, exists
import os, sys, io, urllib, urlparse, json, types, re

from onedrive.conf import ConfigMixin

import logging

log = logging.getLogger(__name__)


class OneDriveInteractionError(Exception): pass

class ProtocolError(OneDriveInteractionError):

	def __init__(self, code, msg, *args):
		assert isinstance(code, (int, types.NoneType)), code
		super(ProtocolError, self).__init__(code, msg, *args)
		self.code = code

class AuthenticationError(OneDriveInteractionError): pass
class AuthMissingError(AuthenticationError): pass
class APIAuthError(AuthenticationError): pass

class NoAPISupportError(OneDriveInteractionError):
	'''Request operation is known to be not supported by the OneDrive API.
		Can be raised on e.g. fallback from regular upload to BITS API due to
			file size limitations, where flags like "overwrite" are not supported (always on).'''

class DoesNotExists(OneDriveInteractionError):
	'Only raised from OneDriveAPI.resolve_path().'


class BITSFragment(object):

	bs = 1 * 2**20

	def __init__(self, src, frag_len):
		self.src, self.pos, self.frag_len = src, src.tell(), frag_len
		self.pos_max = self.pos + self.frag_len

	def fileno(self): return self.src.fileno()

	def seek(self, pos, flags=0):
		assert pos < self.frag_len and flags == 0, [pos, flags]
		self.src.seek(self.pos + pos)

	def read(self, bs=None):
		bs = min(bs, self.pos_max - self.src.tell())\
			if bs is not None else (self.pos_max - self.src.tell())
		return self.src.read(bs)

	def __iter__(self):
		return iter(ft.partial(self.read, self.bs), b'')


class OneDriveHTTPClient(object):

	#: Extra keywords to pass to each "requests.Session.request()" call.
	#: For full list of these see:
	#:  http://docs.python-requests.org/en/latest/api/#requests.Session.request
	request_extra_keywords = None # Example: dict(timeout=(20.0, 10.0))

	#: Keywords to pass to "requests.adapters.HTTPAdapter" subclass init.
	#: Only used with later versions of "requests" than 1.0.0 (where adapters were introduced).
	#: Please do not touch these unless you've
	#:  read requests module documentation on what they actually do.
	request_adapter_settings = None # Example: dict(pool_maxsize=50)

	#: Dict of headers to pass on with each request made.
	#: Can be useful if you want to e.g. disable gzip/deflate
	#:  compression or other http features that are used by default.
	request_base_headers = None

	_requests_setup_done = False
	_requests_base_keywords = None

	def _requests_setup(self, requests, **adapter_kws):
		session, requests_version = None, requests.__version__
		log.debug('Using "requests" module version: %r', requests_version)
		try: requests_version = tuple(it.imap(int, requests_version.split('.')))
		except: requests_version = 999, 0, 0 # most likely some future version

		if requests_version < (0, 14, 0):
			raise RuntimeError( (
				'Version of the "requests" python module (used by python-onedrive)'
					' is incompatible - need at least 0.14.0, but detected {}.'
					' Please update it (or file an issue if it worked before).' )\
				.format(requests.__version__) )

		if requests_version >= (1, 0, 0):
			session = requests.Session()
			session.mount('https://', requests.adapters.HTTPAdapter(**adapter_kws))
		else:
			log.warn( 'Not using request_adapter_settings, as these should not be'
				' supported by detected requests module version: %s', requests_version )

		if hasattr(sys, '_MEIPASS'):
			# Fix cacert.pem path for running from PyInstaller bundle
			cacert_pem = requests.certs.where()
			if not exists(cacert_pem):
				from pkg_resources import resource_filename
				cacert_pem = resource_filename('requests', 'cacert.pem')
			if not exists(cacert_pem):
				cacert_pem = join(sys._MEIPASS, 'requests', 'cacert.pem')
			if not exists(cacert_pem):
				cacert_pem = join(sys._MEIPASS, 'cacert.pem')
			if not exists(cacert_pem):
				raise OneDriveInteractionError(
					'Failed to find requests cacert.pem bundle when running under PyInstaller.' )
			self._requests_base_keywords = (self._requests_base_keywords or dict()).copy()
			self._requests_base_keywords.setdefault('verify', cacert_pem)
			log.debug( 'Adjusted "requests" default ca-bundle'
				' path (to run under PyInstaller) to: %s', cacert_pem )

		if requests_version >= (2, 4, 0):
			# Workaround for https://github.com/certifi/python-certifi/issues/26
			import ssl
			if ssl.OPENSSL_VERSION_INFO < (1, 0, 2):
				try: import certifi
				except ImportError: pass
				else:
					certifi_issue_url = 'https://github.com/certifi/python-certifi/issues/26'
					if hasattr(certifi, 'old_where'): cacert_pem = certifi.old_where()
					else:
						cacert_pem = join(dirname(requests.certs.__file__), 'cacert.pem')
						if not exists(cacert_pem):
							cacert_pem = None
							log.warn( 'Failed to find requests'
								' certificate bundle for woraround to %s', certifi_issue_url )
					if cacert_pem:
						self._requests_base_keywords = (self._requests_base_keywords or dict()).copy()
						self._requests_base_keywords.setdefault('verify', cacert_pem)
						log.debug( 'Adjusted "requests" default ca-bundle path, to work around %s '
							' [OpenSSL version %s, requests %s (>2.4.0) and certifi available at %r], to: %s',
							certifi_issue_url, ssl.OPENSSL_VERSION_INFO,
							requests_version, certifi.__file__, cacert_pem )

		self._requests_setup_done = True
		return session

	def request( self, url, method='get', data=None, files=None,
				raw=False, raw_all=False, headers=dict(), raise_for=dict(), session=None ):
		'''Make synchronous HTTP request.
			Can be overidden to use different http module (e.g. urllib2, twisted, etc).'''
		try: import requests # import here to avoid dependency on the module
		except ImportError as exc:
			exc.args = ( 'Unable to find/import "requests" module.'
				' Please make sure that it is installed, e.g. by running "pip install requests" command.'
				'\nFor more info, visit: http://docs.python-requests.org/en/latest/user/install/',)
			raise exc

		if not self._requests_setup_done:
			patched_session = self._requests_setup(
				requests, **(self.request_adapter_settings or dict()) )
			if patched_session is not None: self._requests_session = patched_session

		if session is None:
			session = getattr(self, '_requests_session', None)
			if not session: session = self._requests_session = requests.session()
		elif not session: session = requests

		method = method.lower()
		kwz = (self._requests_base_keywords or dict()).copy()
		kwz.update(self.request_extra_keywords or dict())
		kwz, func = dict(), ft.partial(session.request, method.upper(), **kwz)
		kwz_headers = (self.request_base_headers or dict()).copy()
		kwz_headers.update(headers)
		if data is not None:
			if method in ['post', 'put']:
				if all(hasattr(data, k) for k in ['seek', 'read']):
					# Force chunked encoding for files, as uploads hang otherwise
					# See https://github.com/mk-fg/python-onedrive/issues/30 for details
					data.seek(0)
					kwz['data'] = iter(ft.partial(data.read, 200 * 2**10), b'')
				else: kwz['data'] = data
			else:
				kwz['data'] = json.dumps(data)
				kwz_headers.setdefault('Content-Type', 'application/json')
		if files is not None:
			# requests-2+ doesn't seem to add default content-type header
			for k, file_tuple in files.iteritems():
				if len(file_tuple) == 2: files[k] = tuple(file_tuple) + ('application/octet-stream',)
				# Rewind is necessary because request can be repeated due to auth failure
				file_tuple[1].seek(0)
			kwz['files'] = files
		if kwz_headers: kwz['headers'] = kwz_headers

		code = res = None
		try:
			res = func(url, **kwz)
			# log.debug('Response headers: %s', res.headers)
			code = res.status_code
			if code == requests.codes.no_content: return
			if code != requests.codes.ok: res.raise_for_status()
		except requests.RequestException as err:
			message = b'{0} [type: {1}, repr: {0!r}]'.format(err, type(err))
			if (res and getattr(res, 'text', None)) is not None: # "res" with non-200 code can be falsy
				message = res.text
				try: message = json.loads(message)
				except: message = '{}: {!r}'.format(str(err), message)[:300]
				else:
					msg_err, msg_data = message.pop('error', None), message
					if msg_err:
						message = '{}: {}'.format(msg_err.get('code', err), msg_err.get('message', msg_err))
						if msg_data: message = '{} (data: {})'.format(message, msg_data)
			raise raise_for.get(code, ProtocolError)(code, message)
		if raw: res = res.content
		elif raw_all: res = code, dict(res.headers.items()), res.content
		else: res = json.loads(res.text)
		return res


class OneDriveAuth(OneDriveHTTPClient):

	#: Client id/secret should be static on per-application basis.
	#: Can be received from LiveConnect by any registered user at:
	#:  https://account.live.com/developers/applications/create
	#: API ToS can be found at:
	#:  http://msdn.microsoft.com/en-US/library/live/ff765012
	client_id = client_secret = None

	auth_url_user = 'https://login.live.com/oauth20_authorize.srf'
	auth_url_token = 'https://login.live.com/oauth20_token.srf'
	auth_scope = 'wl.skydrive', 'wl.skydrive_update', 'wl.offline_access'
	auth_redirect_uri_mobile = 'https://login.live.com/oauth20_desktop.srf'

	#: Set by auth_get_token() method, not used internally.
	#: Might be useful for debugging or extension purposes.
	auth_access_expires = auth_access_data_raw = None

	#: At least one of auth_code, auth_refresh_token
	#:  or auth_access_token should be set before data requests.
	auth_code = auth_refresh_token = auth_access_token = None

	#: This (default) redirect_uri is special - app must be marked as "mobile" to use it.
	auth_redirect_uri = auth_redirect_uri_mobile

	def __init__(self, **config):
		'Initialize API wrapper class with specified properties set.'
		for k, v in config.viewitems():
			try: getattr(self, k)
			except AttributeError:
				raise AttributeError('Unrecognized configuration key: {}'.format(k))
			setattr(self, k, v)

	def auth_user_get_url(self, scope=None):
		'Build authorization URL for User Agent.'
		if not self.client_id: raise AuthMissingError('No client_id specified')
		return '{}?{}'.format(self.auth_url_user, urllib.urlencode(dict(
			client_id=self.client_id, scope=' '.join(scope or self.auth_scope),
			response_type='code', redirect_uri=self.auth_redirect_uri )))

	def auth_user_process_url(self, url):
		'Process tokens and errors from redirect_uri.'
		url = urlparse.urlparse(url)
		url_qs = dict(it.chain.from_iterable(
			urlparse.parse_qsl(v) for v in [url.query, url.fragment] ))
		if url_qs.get('error'):
			raise APIAuthError(
				'{} :: {}'.format(url_qs['error'], url_qs.get('error_description')) )
		self.auth_code = url_qs['code']
		return self.auth_code

	def auth_get_token(self, check_scope=True):
		'Refresh or acquire access_token.'
		res = self.auth_access_data_raw = self._auth_token_request()
		return self._auth_token_process(res, check_scope=check_scope)

	def _auth_token_request(self):
		post_data = dict( client_id=self.client_id,
			client_secret=self.client_secret, redirect_uri=self.auth_redirect_uri )
		if not (self.auth_refresh_token or self.auth_code):
			raise AuthMissingError( 'One of auth_refresh_token'
				' or auth_code must be provided for authentication.' )
		elif not self.auth_refresh_token:
			log.debug('Requesting new access_token through authorization_code grant')
			post_data.update(code=self.auth_code, grant_type='authorization_code')
		else:
			if self.auth_redirect_uri == self.auth_redirect_uri_mobile:
				del post_data['client_secret'] # not necessary for "mobile" apps
			log.debug('Refreshing access_token')
			post_data.update(refresh_token=self.auth_refresh_token, grant_type='refresh_token')
		post_data_missing_keys = list(
			k for k in ['client_id', 'client_secret', 'code', 'refresh_token', 'grant_type']
			if k in post_data and not post_data[k] )
		if post_data_missing_keys:
			raise AuthMissingError( 'Insufficient authentication'
				' data provided (missing keys: {})'.format(post_data_missing_keys) )
		return self.request(self.auth_url_token, method='post', data=post_data)

	def _auth_token_process(self, res, check_scope=True):
		assert res['token_type'] == 'bearer'
		for k in 'access_token', 'refresh_token':
			if k in res: setattr(self, 'auth_{}'.format(k), res[k])
		self.auth_access_expires = None if 'expires_in' not in res\
			else (datetime.utcnow() + timedelta(0, res['expires_in']))
		scope_granted = res.get('scope', '').split()
		if check_scope and set(self.auth_scope) != set(scope_granted):
			raise AuthenticationError(
				'Granted scope ({}) does not match requested one ({}).'
				.format(', '.join(scope_granted), ', '.join(self.auth_scope)) )
		return scope_granted


class OneDriveAPIWrapper(OneDriveAuth):
	'''Less-biased OneDrive API wrapper class.
		All calls made here return result of self.request() call directly,
			so it can easily be made async (e.g. return twisted deferred object)
			by overriding http request method in subclass.'''

	api_url_base = 'https://apis.live.net/v5.0/'

	#: Limit on file uploads via single PUT request, imposed by the API.
	#: Used to opportunistically fallback to BITS API
	#:  (uploads via several http requests) in the "put" method.
	api_put_max_bytes = int(95e6)

	api_bits_url_by_id = (
		'https://cid-{user_id}.users.storage.live.com/items/{folder_id}/{filename}' )
	api_bits_url_by_path = (
		'https://cid-{user_id}.users.storage.live.com'
			'/users/0x{user_id}/LiveFolders/{file_path}' )
	api_bits_protocol_id = '{7df0354d-249b-430f-820d-3d2a9bef4931}'
	api_bits_default_frag_bytes = 10 * 2**20 # 10 MiB
	api_bits_auth_refresh_before_commit_hack = False

	_user_id = None # cached from get_user_id calls

	def _api_url( self, path_or_url, query=dict(),
			pass_access_token=True, pass_empty_values=False ):
		query = query.copy()
		if pass_access_token:
			query.setdefault('access_token', self.auth_access_token)
		if not pass_empty_values:
			for k, v in query.viewitems():
				if not v and v != 0:
					raise AuthMissingError(
						'Empty key {!r} for API call (path/url: {})'.format(k, path_or_url) )
		if re.search(r'^(https?|spdy):', path_or_url):
			if '?' in path_or_url:
				raise AuthMissingError('URL must not include query: {}'.format(path_or_url))
			path_or_url = path_or_url + '?{}'.format(urllib.urlencode(query))
		else:
			path_or_url = urlparse.urljoin(
				self.api_url_base, '{}?{}'.format(path_or_url, urllib.urlencode(query)) )
		return path_or_url

	def _api_url_join(self, *slugs):
		slugs = list(
			urllib.quote(slug.encode('utf-8') if isinstance(slug, unicode) else slug)
			for slug in slugs )
		return ujoin(*slugs)

	def _process_upload_source(self, path_or_tuple):
		name, src = (basename(path_or_tuple), open(path_or_tuple, 'rb'))\
			if isinstance(path_or_tuple, types.StringTypes)\
			else (path_or_tuple[0], path_or_tuple[1])
		if isinstance(src, types.StringTypes): src = io.BytesIO(src)
		return name, src

	def _translate_api_flag(self, val, name=None, special_vals=None):
		if special_vals and val in special_vals: return val
		flag_val_dict = { None: None,
			'false': 'false', False: 'false', 'true': 'true', True: 'true' }
		try: return flag_val_dict[val]
		except KeyError:
			raise ValueError(
				'Parameter{} value must be boolean True/False{}, not {!r}'\
				.format( ' ({!r})'.format(name) if name else '',
						' or one of {}'.format(list(special_vals)) if special_vals else '', val ) )

	def __call__( self, url='me/skydrive', query=dict(), query_filter=True,
				auth_header=False, auto_refresh_token=True, **request_kwz ):
		'''Make an arbitrary call to LiveConnect API.
			Shouldn't be used directly under most circumstances.'''
		if query_filter:
			query = dict((k, v) for k, v in query.viewitems() if v is not None)
		if auth_header:
			request_kwz.setdefault('headers', dict())['Authorization'] =\
				'Bearer {}'.format(self.auth_access_token)
		kwz = request_kwz.copy()
		kwz.setdefault('raise_for', dict())[401] = APIAuthError
		api_url = ft.partial( self._api_url,
			url, query, pass_access_token=not auth_header )
		try: return self.request(api_url(), **kwz)
		except APIAuthError:
			if not auto_refresh_token: raise
			self.auth_get_token()
			if auth_header: # update auth header with a new token
				request_kwz['headers']['Authorization'] =\
					'Bearer {}'.format(self.auth_access_token)
			return self.request(api_url(), **request_kwz)

	def get_quota(self):
		'Get OneDrive object representing quota.'
		return self('me/skydrive/quota')

	def get_user_data(self):
		'Get OneDrive object representing user metadata (including user "id").'
		return self('me')

	def get_user_id(self):
		'Returns "id" of a OneDrive user.'
		if self._user_id is None:
			self._user_id = self.get_user_data()['id']
		return self._user_id

	def listdir(self, folder_id='me/skydrive', limit=None, offset=None):
		'Get OneDrive object representing list of objects in a folder.'
		return self(self._api_url_join(folder_id, 'files'), dict(limit=limit, offset=offset))

	def info(self, obj_id='me/skydrive'):
		'''Return metadata of a specified object.
			See http://msdn.microsoft.com/en-us/library/live/hh243648.aspx
				for the list and description of metadata keys for each object type.'''
		return self(obj_id)

	def get(self, obj_id, byte_range=None):
		'''Download and return a file object or a specified byte_range from it.
			See HTTP Range header (rfc2616) for possible byte_range formats,
			Examples: "0-499" - byte offsets 0-499 (inclusive), "-500" - final 500 bytes.'''
		kwz = dict()
		if byte_range: kwz['headers'] = dict(Range='bytes={}'.format(byte_range))
		return self(self._api_url_join(obj_id, 'content'), dict(download='true'), raw=True, **kwz)

	def put( self, path_or_tuple, folder_id='me/skydrive',
			overwrite=None, downsize=None, bits_api_fallback=True ):
		'''Upload a file (object), possibly overwriting (default behavior)
				a file with the same "name" attribute, if it exists.

			First argument can be either path to a local file or tuple
				of "(name, file)", where "file" can be either a file-like object
				or just a string of bytes.

			overwrite option can be set to False to allow two identically-named
				files or "ChooseNewName" to let OneDrive derive some similar
				unique name. Behavior of this option mimics underlying API.

			downsize is a true/false API flag, similar to overwrite.

			bits_api_fallback can be either True/False or an integer (number of
				bytes), and determines whether method will fall back to using BITS API
				(as implemented by "put_bits" method) for large files. Default "True"
				(bool) value will use non-BITS file size limit (api_put_max_bytes, ~100 MiB)
				as a fallback threshold, passing False will force using single-request uploads.'''
		api_overwrite = self._translate_api_flag(overwrite, 'overwrite', ['ChooseNewName'])
		api_downsize = self._translate_api_flag(downsize, 'downsize')
		name, src = self._process_upload_source(path_or_tuple)

		if not isinstance(bits_api_fallback, (int, float, long)):
			bits_api_fallback = bool(bits_api_fallback)
		if bits_api_fallback is not False:
			if bits_api_fallback is True: bits_api_fallback = self.api_put_max_bytes
			src.seek(0, os.SEEK_END)
			if src.tell() >= bits_api_fallback:
				if bits_api_fallback > 0: # not really a "fallback" in this case
					log.info(
						'Falling-back to using BITS API due to file size (%.1f MiB > %.1f MiB)',
						*((float(v) / 2**20) for v in [src.tell(), bits_api_fallback]) )
				if overwrite is not None and api_overwrite != 'true':
					raise NoAPISupportError( 'Passed "overwrite" flag (value: {!r})'
						' is not supported by the BITS API (always "true" there)'.format(overwrite) )
				if downsize is not None:
					log.info( 'Passed "downsize" flag (value: %r) will not'
						' be used with BITS API, as it is not supported there', downsize )
				file_id = self.put_bits(path_or_tuple, folder_id=folder_id) # XXX: overwrite/downsize
				return self.info(file_id)

		# PUT seem to have better support for unicode
		#  filenames and is recommended in the API docs, see #19.
		# return self( self._api_url_join(folder_id, 'files'),
		# 	dict(overwrite=api_overwrite, downsize_photo_uploads=api_downsize),
		# 	method='post', files=dict(file=(name, src)) )
		return self( self._api_url_join(folder_id, 'files', name),
			dict(overwrite=api_overwrite, downsize_photo_uploads=api_downsize),
			data=src, method='put', auth_header=True )

	def put_bits( self, path_or_tuple,
			folder_id=None, folder_path=None, frag_bytes=None,
			raw_id=False, chunk_callback=None ):
		'''Upload a file (object) using BITS API (via several http requests), possibly
				overwriting (default behavior) a file with the same "name" attribute, if it exists.

			Unlike "put" method, uploads to "folder_path" (instead of folder_id) are
				supported here. Either folder path or id can be specified, but not both.

			Passed "chunk_callback" function (if any) will be called after each
				uploaded chunk with keyword parameters corresponding to
				upload state and BITS session info required to resume it, if necessary.

			Returns id of the uploaded file, as retured by the API
				if raw_id=True is passed, otherwise in a consistent (with other calls)
				"file.{user_id}.{file_id}" format (default).'''
		# XXX: overwrite/downsize are not documented/supported here (yet?)
		name, src = self._process_upload_source(path_or_tuple)

		if folder_id is not None and folder_path is not None:
			raise ValueError('Either "folder_id" or "folder_path" can be specified, but not both.')
		if folder_id is None and folder_path is None: folder_id = 'me/skydrive'
		if folder_id and re.search(r'^me(/.*)$', folder_id): folder_id = self.info(folder_id)['id']
		if not frag_bytes: frag_bytes = self.api_bits_default_frag_bytes

		user_id = self.get_user_id()
		if folder_id: # workaround for API-ids inconsistency between BITS and regular API
			match = re.search( r'^(?i)folder.[a-f0-9]+.'
				'(?P<user_id>[a-f0-9]+(?P<folder_n>!\d+)?)$', folder_id )
			if match and not match.group('folder_n'):
				# root folder is a special case and can't seem to be accessed by id
				folder_id, folder_path = None, ''
			else:
				if not match:
					raise ValueError('Failed to process folder_id for BITS API: {!r}'.format(folder_id))
				folder_id = match.group('user_id')

		if folder_id:
			url = self.api_bits_url_by_id.format(folder_id=folder_id, user_id=user_id, filename=name)
		else:
			url = self.api_bits_url_by_path.format(
				folder_id=folder_id, user_id=user_id, file_path=ujoin(folder_path, name).lstrip('/') )

		code, headers, body = self(
			url, method='post', auth_header=True, raw_all=True,
			headers={
				'X-Http-Method-Override': 'BITS_POST',
				'BITS-Packet-Type': 'Create-Session',
				'BITS-Supported-Protocols': self.api_bits_protocol_id })

		h = lambda k,hs=dict((k.lower(), v) for k,v in headers.viewitems()): hs.get(k, '')
		checks = [ code == 201,
			h('bits-packet-type').lower() == 'ack',
			h('bits-protocol').lower() == self.api_bits_protocol_id.lower(),
			h('bits-session-id') ]
		if not all(checks):
			raise ProtocolError(code, 'Invalid BITS Create-Session response', headers, body, checks)
		bits_sid = h('bits-session-id')

		src.seek(0, os.SEEK_END)
		c, src_len = 0, src.tell()
		cn = src_len / frag_bytes
		if frag_bytes * cn != src_len: cn += 1
		src.seek(0)
		for n in xrange(1, cn+1):
			log.debug( 'Uploading BITS fragment'
				' %s / %s (max-size: %.2f MiB)', n, cn, frag_bytes / float(2**20) )
			frag = BITSFragment(src, frag_bytes)
			c1 = c + frag_bytes
			self(
				url, method='post', raw=True, data=frag,
				headers={
					'X-Http-Method-Override': 'BITS_POST',
					'BITS-Packet-Type': 'Fragment',
					'BITS-Session-Id': bits_sid,
					'Content-Range': 'bytes {}-{}/{}'.format(c, min(c1, src_len)-1, src_len) })
			c = c1

			if chunk_callback:
				chunk_callback(
					bytes_transferred=c, bytes_total=src_len,
					chunks_transferred=n, chunks_total=cn,
					bits_session_id=bits_sid )

		if self.api_bits_auth_refresh_before_commit_hack:
			# As per #39 and comments under the gist with the spec,
			#  apparently this trick fixes occasional http-5XX errors from the API
			self.auth_get_token()

		code, headers, body = self(
			url, method='post', auth_header=True, raw_all=True,
			headers={
				'X-Http-Method-Override': 'BITS_POST',
				'BITS-Packet-Type': 'Close-Session',
				'BITS-Session-Id': bits_sid })
		h = lambda k,hs=dict((k.lower(), v) for k,v in headers.viewitems()): hs.get(k, '')
		checks = [code in [200, 201], h('bits-packet-type').lower() == 'ack' ]
			# int(h('bits-received-content-range') or 0) == src_len -- documented, but missing
			# h('bits-session-id') == bits_sid -- documented, but missing
		if not all(checks):
			raise ProtocolError(code, 'Invalid BITS Close-Session response', headers, body, checks)

		# Workaround for API-ids inconsistency between BITS and regular API
		file_id = h('x-resource-id')
		if not raw_id: file_id = 'file.{}.{}'.format(user_id, file_id)
		return file_id

	def mkdir(self, name=None, folder_id='me/skydrive', metadata=dict()):
		'''Create a folder with a specified "name" attribute.
				folder_id allows to specify a parent folder.
				metadata mapping may contain additional folder properties to pass to an API.'''
		metadata = metadata.copy()
		if name: metadata['name'] = name
		return self(folder_id, data=metadata, method='post', auth_header=True)

	def delete(self, obj_id):
		'Delete specified object.'
		return self(obj_id, method='delete')

	def info_update(self, obj_id, data):
		'''Update metadata with of a specified object.
			See http://msdn.microsoft.com/en-us/library/live/hh243648.aspx
				for the list of RW keys for each object type.'''
		return self(obj_id, method='put', data=data, auth_header=True)

	def link(self, obj_id, link_type='shared_read_link'):
		'''Return a preauthenticated (usable by anyone) link to a
				specified object. Object will be considered "shared" by OneDrive,
				even if link is never actually used.
			link_type can be either "embed" (returns html), "shared_read_link" or "shared_edit_link".'''
		assert link_type in ['embed', 'shared_read_link', 'shared_edit_link']
		return self(self._api_url_join(obj_id, link_type), method='get')

	def copy(self, obj_id, folder_id, move=False):
		'''Copy specified file (object) to a folder with a given ID.
				Well-known folder names (like "me/skydrive")
				don't seem to work here.
			Folders cannot be copied; this is an API limitation.'''
		return self( obj_id,
			method='copy' if not move else 'move',
			data=dict(destination=folder_id), auth_header=True )

	def move(self, obj_id, folder_id):
		'''Move specified file (object) to a folder.
			Note that folders cannot be moved, this is an API limitation.'''
		return self.copy(obj_id, folder_id, move=True)

	def comments(self, obj_id):
		'Get OneDrive object representing a list of comments for an object.'
		return self(self._api_url_join(obj_id, 'comments'))

	def comment_add(self, obj_id, message):
		'Add comment message to a specified object.'
		return self( self._api_url_join(obj_id, 'comments'),
			method='post', data=dict(message=message), auth_header=True )

	def comment_delete(self, comment_id):
		'''Delete specified comment.
			comment_id can be acquired by listing comments for an object.'''
		return self(comment_id, method='delete')


class OneDriveAPI(OneDriveAPIWrapper):
	'''Biased synchronous OneDrive API interface.
		Adds some derivative convenience methods over OneDriveAPIWrapper.'''

	def resolve_path(self, path, root_id='me/skydrive', objects=False, listdir_limit=500):
		'''Return id (or metadata) of an object, specified by chain
				(iterable or fs-style path string) of "name" attributes
				of its ancestors, or raises DoesNotExists error.

			Requires many calls to resolve each name in path, so use with care.
				root_id parameter allows to specify path relative to some folder_id
				(default: me/skydrive).'''
		if path:
			if isinstance(path, types.StringTypes):
				if not path.startswith('me/skydrive'):
					# Split path by both kinds of slashes
					path = filter(None, it.chain.from_iterable(p.split('\\') for p in path.split('/')))
				else: root_id, path = path, None
			if path:
				try:
					for i, name in enumerate(path):
						offset = None
						while True:
							obj_list = self.listdir(root_id, offset=offset, limit=listdir_limit)
							try: root_id = dict(it.imap(op.itemgetter('name', 'id'), obj_list))[name]
							except KeyError:
								if len(obj_list) < listdir_limit: raise # assuming that it's the last page
								offset = (offset or 0) + listdir_limit
							else: break
				except (KeyError, ProtocolError) as err:
					if isinstance(err, ProtocolError) and err.code != 404: raise
					raise DoesNotExists(root_id, path[i:])
		return root_id if not objects else self.info(root_id)

	def get_quota(self):
		'Return tuple of (bytes_available, bytes_quota).'
		return op.itemgetter('available', 'quota')(super(OneDriveAPI, self).get_quota())

	def listdir(self, folder_id='me/skydrive', type_filter=None, limit=None, offset=None):
		'''Return a list of objects in the specified folder_id.
			limit is passed to the API, so might be used as optimization.
			type_filter can be set to type (str) or sequence
				of object types to return, post-api-call processing.'''
		lst = super(OneDriveAPI, self)\
			.listdir(folder_id=folder_id, limit=limit, offset=offset)['data']
		if type_filter:
			if isinstance(type_filter, types.StringTypes): type_filter = {type_filter}
			lst = list(obj for obj in lst if obj['type'] in type_filter)
		return lst

	def copy(self, obj_id, folder_id, move=False):
		'''Copy specified file (object) to a folder.
			Note that folders cannot be copied, this is an API limitation.'''
		if folder_id.startswith('me/skydrive'):
			log.info( 'Special folder names (like "me/skydrive") dont'
				' seem to work with copy/move operations, resolving it to id' )
			folder_id = self.info(folder_id)['id']
		return super(OneDriveAPI, self).copy(obj_id, folder_id, move=move)

	def comments(self, obj_id):
		'Get a list of comments (message + metadata) for an object.'
		return super(OneDriveAPI, self).comments(obj_id)['data']


class PersistentOneDriveAPI(OneDriveAPI, ConfigMixin):

	conf_raise_structure_errors = True

	@ft.wraps(OneDriveAPI.auth_get_token)
	def auth_get_token(self, *argz, **kwz):
		# Wrapped to push new tokens to storage asap.
		ret = super(PersistentOneDriveAPI, self).auth_get_token(*argz, **kwz)
		self.sync()
		return ret

	def __del__(self): self.sync()
