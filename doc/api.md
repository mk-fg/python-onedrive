
* **class onedrive.api\_v5.OneDriveHTTPClient**

    Bases: "object"

    * request\_extra\_keywords = None

        Extra keywords to pass to each "requests.Session.request()"
        call.

        For full list of these see: http://docs.python-requests.org/en/latest/api/#requests.Session.request

    * request\_adapter\_settings = None

        Keywords to pass to "requests.adapters.HTTPAdapter" subclass
        init.

        Only used with later versions of "requests" than 1.0.0 (where
        adapters were introduced).

        Please do not touch these unless you've read requests module
        documentation on what they actually do.

    * request\_base\_headers = None

        Dict of headers to pass on with each request made.

        Can be useful if you want to e.g. disable gzip/deflate
        compression or other http features that are used by default.


    * request(url, method='get', data=None, files=None, raw=False, raw\_all=False, headers={}, raise\_for={}, session=None)

        Make synchronous HTTP request.

        Can be overridden to use different http module (e.g. urllib2,
        twisted, etc).


* **class onedrive.api\_v5.OneDriveAuth(\*\*config)**

    Bases: "onedrive.api\_v5.OneDriveHTTPClient"

    * client\_id = None

        Client id/secret should be static on per-application basis.

        Can be received from LiveConnect by any registered user at:
        https://account.live.com/developers/applications/create

        API ToS can be found at: http://msdn.microsoft.com/en-US/library/live/ff765012

    * client\_secret = None

        Client id/secret should be static on per-application basis.

        Can be received from LiveConnect by any registered user at:
        https://account.live.com/developers/applications/create

        API ToS can be found at: http://msdn.microsoft.com/en-US/library/live/ff765012

    * auth\_url\_user = 'https://login.live.com/oauth20_authorize.srf'

    * auth\_url\_token = 'https://login.live.com/oauth20_token.srf'

    * auth\_scope = ('wl.skydrive', 'wl.skydrive\_update', 'wl.offline\_access')

    * auth\_redirect\_uri\_mobile = 'https://login.live.com/oauth20_desktop.srf'

    * auth\_access\_expires = None

        Set by auth_get_token() method, not used internally.

        Might be useful for debugging or extension purposes.

    * auth\_access\_data\_raw = None

        Set by auth_get_token() method, not used internally.

        Might be useful for debugging or extension purposes.

    * auth\_code = None

        At least one of auth_code, auth_refresh_token or
        auth_access_token should be set before data requests.

    * auth\_refresh\_token = None

        At least one of auth_code, auth_refresh_token or
        auth_access_token should be set before data requests.

    * auth\_access\_token = None

        At least one of auth_code, auth_refresh_token or
        auth_access_token should be set before data requests.

    * auth\_redirect\_uri = 'https://login.live.com/oauth20_desktop.srf'

        This (default) redirect_uri is special - app must be marked as
        "mobile" to use it.


    * \_\_init\_\_(\*\*config)

        Initialize API wrapper class with specified properties set.


    * auth\_user\_get\_url(scope=None)

        Build authorization URL for User Agent.


    * auth\_user\_process\_url(url)

        Process tokens and errors from redirect_uri.


    * auth\_get\_token(check\_scope=True)

        Refresh or acquire access_token.


* **class onedrive.api\_v5.OneDriveAPIWrapper(\*\*config)**

    Bases: "onedrive.api\_v5.OneDriveAuth"

    Less-biased OneDrive API wrapper class.

    All calls made here return result of self.request() call directly,
    so it can easily be made async (e.g. return twisted deferred
    object) by overriding http request method in subclass.

    * api\_url\_base = 'https://apis.live.net/v5.0/'

    * api\_put\_max\_bytes = 95000000

        Limit on file uploads via single PUT request, imposed by the
        API.

        Used to opportunistically fallback to BITS API (uploads via
        several http requests) in the "put" method.

    * api\_bits\_url\_by\_id = 'https://cid-{user_id}.users.storage.live.com/items/{folder_id}/{filename}'

    * api\_bits\_url\_by\_path = 'https://cid-{user_id}.users.storage.live.com/users/0x{user_id}/LiveFolders/{file_path}'

    * api\_bits\_protocol\_id = '{7df0354d-249b-430f-820d-3d2a9bef4931}'

    * api\_bits\_default\_frag\_bytes = 10485760

    * api\_bits\_auth\_refresh\_before\_commit\_hack = False


    * \_\_call\_\_(url='me/skydrive', query={}, query\_filter=True, auth\_header=False, auto\_refresh\_token=True, \*\*request\_kwz)

        Make an arbitrary call to LiveConnect API.

        Shouldn't be used directly under most circumstances.


    * get\_quota()

        Get OneDrive object representing quota.


    * get\_user\_data()

        Get OneDrive object representing user metadata (including user
        "id").


    * get\_user\_id()

        Returns "id" of a OneDrive user.


    * listdir(folder\_id='me/skydrive', limit=None, offset=None)

        Get OneDrive object representing list of objects in a folder.


    * info(obj\_id='me/skydrive')

        Return metadata of a specified object.

        See http://msdn.microsoft.com/en-us/library/live/hh243648.aspx
        for the list and description of metadata keys for each object
        type.


    * get(obj\_id, byte\_range=None)

        Download and return a file object or a specified byte_range from
        it.

        See HTTP Range header (rfc2616) for possible byte_range formats,

        Examples: "0-499" - byte offsets 0-499 (inclusive), "-500" -
        final 500 bytes.


    * put(path\_or\_tuple, folder\_id='me/skydrive', overwrite=None, downsize=None, bits\_api\_fallback=True)

        Upload a file (object), possibly overwriting (default behavior)
        a file with the same "name" attribute, if it exists.

        First argument can be either path to a local file or tuple of
        "(name, file)", where "file" can be either a file-like object or
        just a string of bytes.

        overwrite option can be set to False to allow two identically-
        named files or "ChooseNewName" to let OneDrive derive some
        similar unique name. Behavior of this option mimics underlying
        API.

        downsize is a true/false API flag, similar to overwrite.

        bits_api_fallback can be either True/False or an integer (number
        of bytes), and determines whether method will fall back to using
        BITS API (as implemented by "put_bits" method) for large files.
        Default "True" (bool) value will use non-BITS file size limit
        (api_put_max_bytes, ~100 MiB) as a fallback threshold, passing
        False will force using single-request uploads.


    * put\_bits(path\_or\_tuple, folder\_id=None, folder\_path=None, frag\_bytes=None, raw\_id=False, chunk\_callback=None)

        Upload a file (object) using BITS API (via several http
        requests), possibly overwriting (default behavior) a file with
        the same "name" attribute, if it exists.

        Unlike "put" method, uploads to "folder_path" (instead of
        folder_id) are supported here. Either folder path or id can be
        specified, but not both.

        Passed "chunk_callback" function (if any) will be called after
        each uploaded chunk with keyword parameters corresponding to
        upload state and BITS session info required to resume it, if
        necessary.

        Returns id of the uploaded file, as returned by the API if
        raw_id=True is passed, otherwise in a consistent (with other
        calls) "file.{user_id}.{file_id}" format (default).


    * mkdir(name=None, folder\_id='me/skydrive', metadata={})

        Create a folder with a specified "name" attribute.

        folder_id allows to specify a parent folder.

        metadata mapping may contain additional folder properties to
        pass to an API.


    * delete(obj\_id)

        Delete specified object.


    * info\_update(obj\_id, data)

        Update metadata with of a specified object.

        See http://msdn.microsoft.com/en-us/library/live/hh243648.aspx
        for the list of RW keys for each object type.


    * link(obj\_id, link\_type='shared\_read\_link')

        Return a preauthenticated (usable by anyone) link to a specified
        object. Object will be considered "shared" by OneDrive, even if
        link is never actually used.

        link_type can be either "embed" (returns html),
        "shared_read_link" or "shared_edit_link".


    * copy(obj\_id, folder\_id, move=False)

        Copy specified file (object) to a folder with a given ID. Well-
        known folder names (like "me/skydrive") don't seem to work here.

        Folders cannot be copied; this is an API limitation.


    * move(obj\_id, folder\_id)

        Move specified file (object) to a folder.

        Note that folders cannot be moved, this is an API limitation.


    * comments(obj\_id)

        Get OneDrive object representing a list of comments for an
        object.


    * comment\_add(obj\_id, message)

        Add comment message to a specified object.


    * comment\_delete(comment\_id)

        Delete specified comment.

        comment_id can be acquired by listing comments for an object.


* **class onedrive.api\_v5.OneDriveAPI(\*\*config)**

    Bases: "onedrive.api\_v5.OneDriveAPIWrapper"

    Biased synchronous OneDrive API interface.

    Adds some derivative convenience methods over OneDriveAPIWrapper.


    * resolve\_path(path, root\_id='me/skydrive', objects=False, listdir\_limit=500)

        Return id (or metadata) of an object, specified by chain
        (iterable or fs-style path string) of "name" attributes of its
        ancestors, or raises DoesNotExists error.

        Requires many calls to resolve each name in path, so use with
        care. root_id parameter allows to specify path relative to some
        folder_id (default: me/skydrive).


    * get\_quota()

        Return tuple of (bytes_available, bytes_quota).


    * listdir(folder\_id='me/skydrive', type\_filter=None, limit=None, offset=None)

        Return a list of objects in the specified folder_id.

        limit is passed to the API, so might be used as optimization.

        type_filter can be set to type (str) or sequence of object types
        to return, post-api-call processing.


    * copy(obj\_id, folder\_id, move=False)

        Copy specified file (object) to a folder.

        Note that folders cannot be copied, this is an API limitation.


    * comments(obj\_id)

        Get a list of comments (message + metadata) for an object.


* **class onedrive.api\_v5.PersistentOneDriveAPI(\*\*config)**

    Bases: "onedrive.api\_v5.OneDriveAPI", "onedrive.conf.ConfigMixin"

    * conf\_path\_default = '~/.lcrc'

    * conf\_update\_keys = {'client': set(['secret', 'id']), 'request': set(['base\_headers', 'extra\_keywords', 'adapter\_settings']), 'auth': set(['access\_token', 'code', 'access\_expires', 'refresh\_token'])}


    * from\_conf(path=None, \*\*overrides)

        Initialize instance from YAML configuration file, writing
        updates (only to keys, specified by "conf_update_keys") back to
        it.


* **exception onedrive.api\_v5.OneDriveInteractionError**

    Bases: "exceptions.Exception"


* **exception onedrive.api\_v5.ProtocolError(code, msg, \*args)**

    Bases: "onedrive.api\_v5.OneDriveInteractionError"


    * \_\_init\_\_(code, msg, \*args)


* **exception onedrive.api\_v5.AuthenticationError**

    Bases: "onedrive.api\_v5.OneDriveInteractionError"


* **exception onedrive.api\_v5.AuthMissingError**

    Bases: "onedrive.api\_v5.AuthenticationError"


* **exception onedrive.api\_v5.APIAuthError**

    Bases: "onedrive.api\_v5.AuthenticationError"


* **exception onedrive.api\_v5.NoAPISupportError**

    Bases: "onedrive.api\_v5.OneDriveInteractionError"

    Request operation is known to be not supported by the OneDrive API.

    Can be raised on e.g. fallback from regular upload to BITS API due
    to file size limitations, where flags like "overwrite" are not
    supported (always on).


* **exception onedrive.api\_v5.DoesNotExists**

    Bases: "onedrive.api\_v5.OneDriveInteractionError"

    Only raised from OneDriveAPI.resolve_path().
