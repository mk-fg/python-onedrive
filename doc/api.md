* **class skydrive.api\_v5.SkyDriveAuth(\*\*config)**

    Bases: "object"

    * client\_id = None

        Client id/secret should be static on per-application basis.

        Can be received from LiveConnect by any registered user at
        https://manage.dev.live.com/

        API ToS can be found here at http://msdn.microsoft.com/en-
        US/library/live/ff765012

    * client\_secret = None

        Client id/secret should be static on per-application basis.

        Can be received from LiveConnect by any registered user at
        https://manage.dev.live.com/

        API ToS can be found here at http://msdn.microsoft.com/en-
        US/library/live/ff765012

    * auth\_url\_user = 'https://login.live.com/oauth20_authorize.srf'

    * auth\_url\_token = 'https://login.live.com/oauth20_token.srf'

    * auth\_scope = ('wl.skydrive', 'wl.skydrive\_update', 'wl.offline\_access')

    * auth\_redirect\_uri\_mobile = 'https://login.live.com/oauth20_desktop.srf'

    * auth\_access\_expires = None

        Set by auth_get_token, not used internally

    * auth\_access\_data\_raw = None

        Set by auth_get_token, not used internally

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

        This (default) redirect_uri is **special** - app must be marked
        as "mobile" to use it.


    * \_\_init\_\_(\*\*config)

        Initialize API wrapper class with specified properties set.


    * auth\_user\_get\_url(scope=None)

        Build authorization URL for User Agent.


    * auth\_user\_process\_url(url)

        Process tokens and errors from redirect_uri.


    * auth\_get\_token(check\_scope=True)

        Refresh or acquire access_token.

* **class skydrive.api\_v5.SkyDriveAPI(\*\*config)**

    Bases: "skydrive.api\_v5.SkyDriveAuth"

    * api\_url\_base = 'https://apis.live.net/v5.0/'


    * \_\_call\_\_(url='me/skydrive', query={}, query\_filter=True, auth\_header=False, auto\_refresh\_token=True, \*\*request\_kwz)

        Make an arbitrary call to LiveConnect API.

        Shouldn't be used directly under most circumstances.


    * get\_quota()

        Return tuple of (bytes_available, bytes_quota).


    * info(obj\_id='me/skydrive')

        Return metadata of a specified object.

        See http://msdn.microsoft.com/en-us/library/live/hh243648.aspx
        for the list and description of metadata keys for each object
        type.


    * listdir(folder\_id='me/skydrive', type\_filter=None, limit=None)

        Return a list of objects in the specified folder_id.

        limit is passed to the API, so might be used as optimization.

        type_filter can be set to type (str) or sequence of object types
        to return, post-api-call processing.


    * resolve\_path(path, root\_id='me/skydrive', objects=False)

        Return id (or metadata) of an object, specified by chain
        (iterable or fs-style path string) of "name" attributes of it's
        ancestors.

        Requires a lot of calls to resolve each name in path, so use
        with care.

        root_id parameter allows to specify path relative to some
        folder_id (default: me/skydrive).


    * get(obj\_id, byte\_range=None)

        Download and return an file (object) or a specified byte_range
        from it.

        See HTTP Range header (rfc2616) for possible byte_range formats,
        some examples: "0-499" - byte offsets 0-499 (inclusive), "-500"
        \- final 500 bytes.


    * put(path, folder\_id='me/skydrive', overwrite=True)

        Upload a file (object), possibly overwriting (default behavior)
        a file with the same "name" attribute, if exists.

        overwrite option can be set to False to allow two identically-
        named files or "ChooseNewName" to let SkyDrive derive some
        similar unique name. Behavior of this option mimics underlying
        API.


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

        Return a preauthenticated (useable by anyone) link to a
        specified object.

        Object will be considered "shared" by SkyDrive, even if link is
        never actually used.

        link_type can be either "embed" (returns html),
        "shared_read_link" or "shared_edit_link".


    * copy(obj\_id, folder\_id, move=False)

        Copy specified file (object) to a folder.

        Note that folders cannot be copied, this is API limitation.


    * move(obj\_id, folder\_id)

        Move specified file (object) to a folder.

        Note that folders cannot be moved, this is API limitation.


    * comments(obj\_id)

        Get a list of comments (message + metadata) for an object.


    * comment\_add(obj\_id, message)

        Add comment message to a specified object.


    * comment\_delete(comment\_id)

        Delete specified comment.

        comment_id can be acquired by listing comments for an object.

* **class skydrive.api\_v5.PersistentSkyDriveAPI(\*\*config)**

    Bases: "skydrive.api\_v5.SkyDriveAPI", "skydrive.conf.ConfigMixin"

* **exception skydrive.api\_v5.SkyDriveInteractionError**

    Bases: "exceptions.Exception"

* **exception skydrive.api\_v5.ProtocolError(msg, code=None)**

    Bases: "skydrive.api\_v5.SkyDriveInteractionError"


    * \_\_init\_\_(msg, code=None)

* **exception skydrive.api\_v5.AuthenticationError**

    Bases: "skydrive.api\_v5.SkyDriveInteractionError"
