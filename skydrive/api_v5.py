#-*- coding: utf-8 -*-
from __future__ import print_function


import itertools as it, operator as op, functools as ft
import os, sys, math, urllib, urlparse
import requests



class SkyDriveInteractionError(Exception): pass

class ProtocolError(SkyDriveInteractionError): pass
class AuthenticationError(SkyDriveInteractionError): pass


def request_post(url, data):
	try:
		return requests.post( url,
			data=data, config=dict(danger_mode=True) ).json
	except requests.RequestException as err:
		raise ProtocolError(err.message)

def urandom_hex(n):
	return os.urandom(int(math.ceil(n / 2.0))).encode('hex')[:n]



class SkyDriveAPIv5(object):

	# Should be static on per-application basis.
	# Can be received from LiveConnect by any registered user at https://manage.dev.live.com/
	# API ToS can be found here at http://msdn.microsoft.com/en-US/library/live/ff765012
	client_id = client_secret = None

	# At least one of these should be set before data requests.
	auth_code = auth_refresh_token = auth_access_token = None

	# This (default) redirect_uri is **special** - app must be marked as "mobile" to use it.
	auth_redirect_uri = 'https://login.live.com/oauth20_desktop.srf'

	auth_url_user = 'https://login.live.com/oauth20_authorize.srf'
	auth_url_token = 'https://login.live.com/oauth20_token.srf'
	auth_scope = 'wl.skydrive', 'wl.skydrive_update', 'wl.offline_access'


	def __init__(self, client_id=None, client_secret=None, urandom_len=16, **config):
		self.client_id = client_id or urandom_hex(urandom_len)
		self.client_secret = client_secret or urandom_hex(urandom_len)

		for k, v in config.viewitems():
			try: getattr(self, k)
			except AttributeError:
				raise AttributeError('Unrecognized configuration key: {}'.format(k))
			setattr(self, k, v)

	@classmethod
	def from_lcrc(cls):
		import yaml
		return cls(**yaml.load(open(os.path.expanduser('~/.lcrc')).read()))


	def auth_user_get_url(self, scope=None, redirect_uri=None):
		# Note: default redirect_uri is **special**, app must be marked as "mobile" to use it
		return '{}?{}'.format( self.auth_url_user, urllib.urlencode(dict(
			client_id=self.client_id, scope=' '.join(scope or self.auth_scope),
			response_type='code', redirect_uri=redirect_uri or self.auth_redirect_uri )) )

	def auth_user_process_url(self, url):
		url = urlparse.urlparse(url)
		url_qs = dict(it.chain.from_iterable(
			urlparse.parse_qsl(v) for v in [url.query, url.fragment] ))
		if url_qs.get('error'):
			raise AuthenticationError('{} :: {}'.format(
				url_qs['error'], url_qs.get('error_description') ))
		self.auth_code = url_qs['code']
		return self.auth_code

	def auth_get_token(self, refresh_token=None):
		if refresh_token is None:
			if not self.auth_refresh_token and not self.auth_code:
				raise AuthenticationError( 'Either code or refresh_token'
					' is necessary to request access_token, but neither one was provided.' )
			refresh_token = self.auth_refresh_token
		res = request_post(
			data=dict(code=self.auth_code, grant_type='authorization_code')
				if not refresh_token else
				dict(refresh_token=refresh_token, grant_type='refresh_token') )
		for k in 'access_token', 'refresh_token':
			if k in res: setattr(self, 'auth_{}'.format(k), res[k])
		print(res)


if __name__ == '__main__':
	api = SkyDriveAPIv5.from_lcrc()
	# print(api.auth_user_get_url())
	api.auth_user_process_url( 'https://login.live.com/'
		'oauth20_desktop.srf?code=d47e2f08-0851-cf5c-86c7-8fdcd9db128c&lc=1033' )
	# api.auth_get_token(
