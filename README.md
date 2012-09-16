python-skydrive
--------------------

Python interface to [SkyDrive
API](http://msdn.microsoft.com/en-us/library/live/hh826521).

This module allows to access data on Microsoft SkyDrive cloud storage from
python code, abstracting authentication, http requests and response processing
to a simple python methods.

Under heavy development, not ready for general usage yet.


API notes
--------------------

Important: these details can (naturally) go obsolete, especially if timestamp of
this doc is older than the one of the API docs, in which case please open an
Issue pointing to the inconsistency.

It's quite a conventional REST API with JSON encoding of structured data, like
pretty much every other trendy modern API, say, github.

Permissions are set per-path, are inherited for the created objects and
**cannot** be changed through the API, only through the Web UI (or maybe
proprietary windows interfaces as well).

Accessible to everyone URL links (of different types - embedded, read-only,
read-write, preauthenticated) to any restricted-access object (that is reachable
through the API) can be provided though (recursive?), a bit like in tahoe-lafs,
but probably without the actual crypto keys embedded in them (not much point as
they're kept server-side along with the files anyway).

Authentication is "[OAuth
2.0](http://msdn.microsoft.com/en-us/library/live/hh243647.aspx)", which is
quite ambigous all by itself, and especially when being implemented by
well-known for it's proprietary "cripple-everything-else" extension creep
Microsoft.

All but a few default paths (like "my_documents") are accessed by file/folder
IDs, which are not derived from their names or paths in any obvious way and look
like "folder.a6b2a7e8f2515e5e.A6B2A7E8F2515E5E!110".
UI-visible names come on top of these as metadata.

There are some handy special API URLs for stuff like quota and a list of recent
changes.

Errors can be returned for most ops, encoded as JSON in responses and have a
human-readable "code" (like "resource_quota_exceeded") and descriptive
"message".

API allows to request image-previews of an items.

According to [SkyDrive interaction
guidelines](http://msdn.microsoft.com/en-us/library/live/hh826545#guidelines),
it is discouraged (though not explicitly prohibited) to upload files in
non-conventional formats that aren't useable to other apps (under "Use SkyDrive
for the things that it’s good at"):

	To support this principle, the Live Connect APIs limit the set of file formats
	that apps can upload to SkyDrive.

[ToS for LiveConnect APIs](http://msdn.microsoft.com/en-US/library/live/ff765012)
is kinda weird, having unclear (at least to layman like me) stuff like this:

* You may only use the Live SDK and Live Connect APIs to create software.

	Seem to imply that APIs shouldn't be used in hardware, but I fail to see why
	it can't also be interpreted as "only create software, not just use it to
	get/store stuff".

* You are solely and entirely responsible for all uses of Live Connect occurring
	under your Client ID.

	So either you take the blame for every potential user or go make all users
	register their own app? Hopefully I've misinterpreted that one.
