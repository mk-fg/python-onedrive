#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import os
import urllib
import urlparse
import json
import types
import itertools as it
import operator as op
import functools as ft

from datetime import datetime, timedelta
from posixpath import join as ujoin # used for url pahs
from os.path import join, basename

from onedrive.conf import ConfigMixin

import logging

log = logging.getLogger(__name__)


class OneDriveInteractionError(Exception):
    pass


class ProtocolError(OneDriveInteractionError):
    def __init__(self, code, msg):
        super(ProtocolError, self).__init__(code, msg)
        self.code = code


class AuthenticationError(OneDriveInteractionError):
    pass


class DoesNotExists(OneDriveInteractionError):
    """Only raised from OneDriveAPI.resolve_path()."""


class OneDriveHTTPClient(object):
    def _requests_tls_workarounds(self, requests):
        # Workaround for TLSv1.2 issue with Microsoft livefilestore.com hosts.
        session = None

        if requests.__version__ in ['0.14.1', '0.14.2']:
            # These versions can only be monkey-patched, unfortunately.
            # See README and following related links for details:
            #  https://github.com/mk-fg/python-onedrive/issues/1
            #  https://github.com/kennethreitz/requests/pull/799
            #  https://github.com/kennethreitz/requests/pull/900
            #  https://github.com/kennethreitz/requests/issues/1083
            #  https://github.com/shazow/urllib3/pull/109

            try:
                from requests.packages.urllib3 import connectionpool as cp
            except ImportError:
                from urllib3 import connectionpool as cp

            socket, ssl, match_hostname = cp.socket, cp.ssl, cp.match_hostname

            class VerifiedHTTPSConnection(cp.VerifiedHTTPSConnection):
                def connect(self):
                    sock = socket.create_connection((self.host, self.port),
                                                    self.timeout)

                    self.sock = ssl.wrap_socket(sock,
                                                self.key_file,
                                                self.cert_file,
                                                cert_reqs=self.cert_reqs,
                                                ca_certs=self.ca_certs,
                                                ssl_version=ssl.PROTOCOL_TLSv1)
                    if self.ca_certs:
                        match_hostname(self.sock.getpeercert(), self.host)

            cp.VerifiedHTTPSConnection = VerifiedHTTPSConnection

        else:
            version = tuple(it.imap(int, requests.__version__.split('.')))
            if version > (1, 0, 0):
                # Less hacks necessary - session HTTPAdapter can be used
                try:
                    from requests.packages.urllib3.poolmanager import PoolManager
                except ImportError:
                    from urllib3.poolmanager import PoolManager

                from requests.adapters import HTTPAdapter
                import ssl

                _default_block = object()

                class TLSv1Adapter(HTTPAdapter):
                    def init_poolmanager(self, connections, maxsize,
                                         block=_default_block):
                        pool_kw = dict()
                        if block is _default_block:
                            try:
                                # 1.2.1+
                                from requests.adapters import DEFAULT_POOLBLOCK
                            except ImportError:
                                pass
                            else:
                                pool_kw['block'] = DEFAULT_POOLBLOCK
                        self.poolmanager = PoolManager(
                            num_pools=connections, maxsize=maxsize,
                            ssl_version=ssl.PROTOCOL_TLSv1, **pool_kw)

                session = requests.Session()
                session.mount('https://', TLSv1Adapter())

        requests._onedrive_tls_fixed = True
        return session

    def request(self, url, method='get', data=None,
                files=None, raw=False, headers=dict(), raise_for=dict(),
                session=None):
        """Make synchronous HTTP request.
            Can be overidden to use different http module
            (e.g. urllib2, twisted, etc)."""

        import requests  # import here to avoid dependency on the module

        if not getattr(requests, '_onedrive_tls_fixed', False):
            # temp fix for https://github.com/mk-fg/python-onedrive/issues/1
            patched_session = self._requests_tls_workarounds(requests)
            if patched_session is not None:
                self._requests_session = patched_session

        if session is None:
            try:
                session = self._requests_session
            except AttributeError:
                session = self._requests_session = requests.session()
        elif not session:
            session = requests

        method = method.lower()
        kwz, func = dict(), getattr(session, method,
                                    ft.partial(session.request, method.upper())
                                    )
        if data is not None:
            if method in ['post', 'put']:
                kwz['data'] = data
            else:
                kwz['data'] = json.dumps(data)
                headers = headers.copy()
                headers.setdefault('Content-Type', 'application/json')
        if files is not None:
            # requests-2+ doesn't seem to add default content-type header
            for k, file_tuple in files.iteritems():
                if len(file_tuple) == 2:
                    files[k] = tuple(file_tuple) + ('application/octet-stream',)
                # rewind is necessary because request can be repeated due to auth failure
                file_tuple[1].seek(0)
            kwz['files'] = files
        if headers is not None:
            kwz['headers'] = headers
        code = res = None
        try:
            res = func(url, **kwz)
            # log.debug('Response headers: {}'.format(res.headers))
            code = res.status_code
            if code == requests.codes.no_content:
                return
            if code != requests.codes.ok:
                res.raise_for_status()
            return json.loads(res.text) if not raw else res.content
        except requests.RequestException as err:
            try:
                if res is None:
                    raise ValueError
                message = res.json()['error']
            except (ValueError, KeyError):
                message = err.message
            raise raise_for.get(code, ProtocolError)(code, message)


class OneDriveAuth(OneDriveHTTPClient):
    #: Client id/secret should be static on per-application basis.
    #: Can be received from LiveConnect by any registered user at
    #: https://manage.dev.live.com/

    #: API ToS can be found at
    #: http://msdn.microsoft.com/en-US/library/live/ff765012

    client_id = client_secret = None

    auth_url_user = 'https://login.live.com/oauth20_authorize.srf'
    auth_url_token = 'https://login.live.com/oauth20_token.srf'
    auth_scope = 'wl.skydrive', 'wl.skydrive_update', 'wl.offline_access'
    auth_redirect_uri_mobile = 'https://login.live.com/oauth20_desktop.srf'

    #: Set by auth_get_token() method, not used internally.
    #: Might be useful for debugging or extension purposes.
    auth_access_expires = auth_access_data_raw = None

    #: At least one of auth_code, auth_refresh_token or auth_access_token
    #: should be set before data requests.
    auth_code = auth_refresh_token = auth_access_token = None

    #: This (default) redirect_uri is special -
    #: app must be marked as "mobile" to use it.
    auth_redirect_uri = auth_redirect_uri_mobile

    def __init__(self, **config):
        """Initialize API wrapper class with specified properties set."""
        for k, v in config.viewitems():
            try:
                getattr(self, k)
            except AttributeError:
                raise AttributeError('Unrecognized configuration key: {}'
                                     .format(k))
            setattr(self, k, v)

    def auth_user_get_url(self, scope=None):
        """Build authorization URL for User Agent."""
        if not self.client_id:
            raise AuthenticationError('No client_id specified')
        return '{}?{}'.format(self.auth_url_user, urllib.urlencode(dict(
            client_id=self.client_id, scope=' '.join(scope or self.auth_scope),
            response_type='code', redirect_uri=self.auth_redirect_uri)))

    def auth_user_process_url(self, url):
        """Process tokens and errors from redirect_uri."""
        url = urlparse.urlparse(url)
        url_qs = dict(it.chain.from_iterable(
            urlparse.parse_qsl(v) for v in [url.query, url.fragment]))
        if url_qs.get('error'):
            raise AuthenticationError('{} :: {}'.format(
                url_qs['error'], url_qs.get('error_description')))
        self.auth_code = url_qs['code']
        return self.auth_code

    def auth_get_token(self, check_scope=True):
        """Refresh or acquire access_token."""
        res = self.auth_access_data_raw = self._auth_token_request()
        return self._auth_token_process(res, check_scope=check_scope)

    def _auth_token_request(self):
        post_data = dict(client_id=self.client_id,
                         client_secret=self.client_secret,
                         redirect_uri=self.auth_redirect_uri)
        if not self.auth_refresh_token:
            log.debug(
                'Requesting new access_token through authorization_code grant')

            post_data.update(code=self.auth_code,
                             grant_type='authorization_code')

        else:
            if self.auth_redirect_uri == self.auth_redirect_uri_mobile:
                # not necessary for "mobile" apps
                del post_data['client_secret']

            log.debug('Refreshing access_token')

            post_data.update(refresh_token=self.auth_refresh_token,
                             grant_type='refresh_token')

        post_data_missing_keys = list(k for k in ['client_id', 'client_secret',
                                                  'code', 'refresh_token',
                                                  'grant_type']
                                      if k in post_data and not post_data[k])
        if post_data_missing_keys:
            raise AuthenticationError('Insufficient authentication'
                                      ' data provided (missing keys: {})'
                                      .format(post_data_missing_keys))

        return self.request(self.auth_url_token, method='post', data=post_data)

    def _auth_token_process(self, res, check_scope=True):
        assert res['token_type'] == 'bearer'
        for k in 'access_token', 'refresh_token':
            if k in res:
                setattr(self, 'auth_{}'.format(k), res[k])
        self.auth_access_expires = None if 'expires_in' not in res \
            else (datetime.utcnow() + timedelta(0, res['expires_in']))

        scope_granted = res.get('scope', '').split()
        if check_scope and set(self.auth_scope) != set(scope_granted):
            raise AuthenticationError(
                "Granted scope ({}) doesn't match requested one ({})."
                .format(', '.join(scope_granted), ', '.join(self.auth_scope)))
        return scope_granted


class OneDriveAPIWrapper(OneDriveAuth):
    """Less-biased OneDrive API wrapper class.
        All calls made here return result of self.request() call directly,
        so it can easily be made async (e.g. return twisted deferred object)
        by overriding http request method in subclass."""

    api_url_base = 'https://apis.live.net/v5.0/'

    def _api_url(self, path, query=dict(),
                 pass_access_token=True, pass_empty_values=False):
        query = query.copy()

        if pass_access_token:
            query.setdefault('access_token', self.auth_access_token)

        if not pass_empty_values:
            for k, v in query.viewitems():
                if not v and v != 0:
                    raise AuthenticationError(
                        'Empty key {!r} for API call (path: {})'
                        .format(k, path))

        return urlparse.urljoin(self.api_url_base,
                                '{}?{}'.format(path, urllib.urlencode(query)))

    def __call__(self, url='me/skydrive', query=dict(), query_filter=True,
                 auth_header=False, auto_refresh_token=True, **request_kwz):
        """Make an arbitrary call to LiveConnect API.
            Shouldn't be used directly under most circumstances."""
        if query_filter:
            query = dict((k, v) for k, v in
                         query.viewitems() if v is not None)
        if auth_header:
            request_kwz.setdefault('headers', dict())['Authorization'] = (
                'Bearer {}'.format(self.auth_access_token))

        kwz = request_kwz.copy()
        kwz.setdefault('raise_for', dict())[401] = AuthenticationError
        api_url = ft.partial(self._api_url,
                             url, query, pass_access_token=not auth_header)
        try:
            return self.request(api_url(), **kwz)

        except AuthenticationError:
            if not auto_refresh_token:
                raise
            self.auth_get_token()
            if auth_header:  # update auth header with a new token
                request_kwz['headers']['Authorization'] \
                    = 'Bearer {}'.format(self.auth_access_token)
            return self.request(api_url(), **request_kwz)

    def get_quota(self):
        """Get OneDrive object, representing quota."""
        return self('me/skydrive/quota')

    def listdir(self, folder_id='me/skydrive', limit=None, offset=None):
        """Get OneDrive object, representing list of objects in a folder."""
        return self(ujoin(folder_id, 'files'), dict(limit=limit, offset=offset))

    def info(self, obj_id='me/skydrive'):
        """Return metadata of a specified object.
            See http://msdn.microsoft.com/en-us/library/live/hh243648.aspx
            for the list and description of metadata keys for
            each object type."""
        return self(obj_id)

    def get(self, obj_id, byte_range=None):
        """Download and return a file object or a specified byte_range from it.
            See HTTP Range header (rfc2616) for possible byte_range formats,
            Examples: "0-499" - byte offsets 0-499 (inclusive),
                      "-500" - final 500 bytes."""
        kwz = dict()
        if byte_range:
            kwz['headers'] = dict(Range='bytes={}'.format(byte_range))
        return self(ujoin(obj_id, 'content'), dict(download='true'),
                    raw=True, **kwz)

    def put(self, path_or_tuple, folder_id='me/skydrive', overwrite=True):
        """Upload a file (object), possibly overwriting (default behavior)
            a file with the same "name" attribute, if it exists.

            First argument can be either path to a local file or tuple
             of "(name, file)", where "file" can be either a file-like object
             or just a string of bytes.

            overwrite option can be set to False to allow two identically-named
             files or "ChooseNewName" to let OneDrive derive some similar
             unique name. Behavior of this option mimics underlying API."""

        if overwrite is not None:
            if overwrite is False:
                overwrite = 'false'
            elif overwrite in ('true', True):
                overwrite = None  # don't pass it
            elif overwrite != 'ChooseNewName':
                raise ValueError('overwrite parameter'
                                 ' must be True, False or "ChooseNewName".')
        name, src = (basename(path_or_tuple), open(path_or_tuple, 'rb')) \
            if isinstance(path_or_tuple, types.StringTypes) \
            else (path_or_tuple[0], path_or_tuple[1])

        return self(ujoin(folder_id, 'files', name),
                    dict(overwrite=overwrite),
                    data=src, method='put', auth_header=True)

    def mkdir(self, name=None, folder_id='me/skydrive', metadata=dict()):
        """Create a folder with a specified "name" attribute.
            folder_id allows to specify a parent folder. metadata mapping may
            contain additional folder properties to pass to an API."""
        metadata = metadata.copy()
        if name:
            metadata['name'] = name
        return self(folder_id, data=metadata, method='post', auth_header=True)

    def delete(self, obj_id):
        'Delete specified object.'
        return self(obj_id, method='delete')

    def info_update(self, obj_id, data):
        """Update metadata with of a specified object.
            See http://msdn.microsoft.com/en-us/library/live/hh243648.aspx
            for the list of RW keys for each object type."""
        return self(obj_id, method='put', data=data, auth_header=True)

    def link(self, obj_id, link_type='shared_read_link'):
        """Return a preauthenticated (usable by anyone) link to a
            specified object. Object will be considered "shared" by OneDrive,
            even if link is never actually used.

           link_type can be either "embed" (returns html), "shared_read_link"
            or "shared_edit_link"."""

        assert link_type in ['embed', 'shared_read_link', 'shared_edit_link']
        return self(ujoin(obj_id, link_type), method='get')

    def copy(self, obj_id, folder_id, move=False):
        """Copy specified file (object) to a folder with a given ID.
            Well-known folder names (like "me/skydrive")
            don't seem to work here.

           Folders cannot be copied; this is an API limitation."""
        return self(obj_id,
                    method='copy' if not move else 'move',
                    data=dict(destination=folder_id), auth_header=True)

    def move(self, obj_id, folder_id):
        """Move specified file (object) to a folder.
            Note that folders cannot be moved, this is API limitation."""
        return self.copy(obj_id, folder_id, move=True)

    def comments(self, obj_id):
        """Get OneDrive object, representing a list of comments
            for an object."""
        return self(ujoin(obj_id, 'comments'))

    def comment_add(self, obj_id, message):
        """Add comment message to a specified object."""
        return self(ujoin(obj_id, 'comments'), method='post',
                    data=dict(message=message), auth_header=True)

    def comment_delete(self, comment_id):
        """Delete specified comment.
            comment_id can be acquired by listing comments for an object."""
        return self(comment_id, method='delete')


class OneDriveAPI(OneDriveAPIWrapper):
    """Biased synchronous OneDrive API interface.
        Adds some derivative convenience methods over OneDriveAPIWrapper."""

    def resolve_path(self, path,
                     root_id='me/skydrive', objects=False):
        """Return id (or metadata) of an object, specified by chain
            (iterable or fs-style path string) of "name" attributes of
            its ancestors, or raises DoesNotExists error.

           Requires many calls to resolve each name in path, so use with care.
            root_id parameter allows to specify path relative to some folder_id
            (default: me/skydrive)."""
        if path:
            if isinstance(path, types.StringTypes):
                if not path.startswith('me/skydrive'):
                    path = filter(None, path.split(os.sep))
                else:
                    root_id, path = path, None
            if path:
                try:
                    for i, name in enumerate(path):
                        root_id = dict(it.imap(op.itemgetter('name', 'id'),
                                               self.listdir(root_id)))[name]
                except (KeyError, ProtocolError) as err:
                    if isinstance(err, ProtocolError) and err.code != 404:
                        raise
                    raise DoesNotExists(root_id, path[i:])
        return root_id if not objects else self.info(root_id)

    def get_quota(self):
        """Return tuple of (bytes_available, bytes_quota)."""
        return (op.itemgetter('available', 'quota')(
                super(OneDriveAPI, self).get_quota()))

    def listdir(self, folder_id='me/skydrive', type_filter=None, limit=None, offset=None):
        """Return a list of objects in the specified folder_id.
            limit is passed to the API, so might be used as optimization.
            type_filter can be set to type (str) or sequence
            of object types to return, post-api-call processing."""
        lst = super(OneDriveAPI, self).listdir(folder_id=folder_id,
                                               limit=limit,
                                               offset=offset)['data']
        if type_filter:
            if isinstance(type_filter, types.StringTypes):
                type_filter = {type_filter}
            lst = list(obj for obj in lst if obj['type'] in type_filter)
        return lst

    def copy(self, obj_id, folder_id, move=False):
        """Copy specified file (object) to a folder.
            Note that folders cannot be copied, this is API limitation."""
        if folder_id.startswith('me/skydrive'):
            log.info(
                "Special folder names (like 'me/skydrive') don't"
                " seem to work with copy/move operations, resolving it to id")
            folder_id = self.info(folder_id)['id']
        return super(OneDriveAPI, self).copy(obj_id, folder_id, move=move)

    def comments(self, obj_id):
        """Get a list of comments (message + metadata) for an object."""
        return super(OneDriveAPI, self).comments(obj_id)['data']


class PersistentOneDriveAPI(OneDriveAPI, ConfigMixin):
    conf_raise_structure_errors = True

    @ft.wraps(OneDriveAPI.auth_get_token)
    def auth_get_token(self, *argz, **kwz):
        # Wrapped to push new tokens to storage asap.
        ret = super(PersistentOneDriveAPI, self).auth_get_token(*argz, **kwz)
        self.sync()
        return ret

    def __del__(self):
        self.sync()
