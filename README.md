python-skydrive
----------------------------------------

Python and command-line interface for [SkyDrive API (version
5.0)](http://msdn.microsoft.com/en-us/library/live/hh826521).

This module allows to access data on Microsoft SkyDrive cloud storage from
python code, abstracting authentication, http requests and response processing
to a simple python methods.

Also comes with command-line tool to conveniently browse and manipulate SkyDrive
contents from interactive shell or scripts.



Installation
----------------------------------------

It's a regular package for Python 2.7 (not 3.X).

Using [pip](http://pip-installer.org/) is the best way:

	% pip install python-skydrive

If you don't have it, use:

	% easy_install pip
	% pip install python-skydrive

Alternatively ([see
also](http://www.pip-installer.org/en/latest/installing.html)):

	% curl https://raw.github.com/pypa/pip/master/contrib/get-pip.py | python
	% pip install python-skydrive

Or, if you absolutely must:

	% easy_install python-skydrive

But, you really shouldn't do that.

Current-git version can be installed like this:

	% pip install 'git+https://github.com/mk-fg/python-skydrive.git#egg=python-skydrive'

Note that to install stuff in system-wide PATH and site-packages, elevated
privileges are often required.
Use "install --user",
[~/.pydistutils.cfg](http://docs.python.org/install/index.html#distutils-configuration-files)
or [virtualenv](http://pypi.python.org/pypi/virtualenv) to do unprivileged
installs into custom paths.

Alternatively, `./skydrive-cli` tool can be run right from the checkout tree
without any installation, if that's the only thing you need there.


### Requirements

* [Python 2.7 (not 3.X)](http://python.org/)

* [requests](http://docs.python-requests.org/en/latest/)

* (optional, recommended) [PyYAML](http://pyyaml.org) - required for CLI tool
	and optional persistent-state ("conf") module only.



LiveConnect/SkyDrive API (v5.0) notes
----------------------------------------

Important: these details can (naturally) go obsolete, especially if timestamp of
this doc is older than the one of the API docs, in which case please open an
Issue pointing to the inconsistency.

It's quite a conventional REST API with JSON encoding of structured data, like
pretty much every other trendy modern API, say, github.

Authentication is ["OAuth
2.0"](http://msdn.microsoft.com/en-us/library/live/hh243647.aspx), which is
quite ambigous all by itself, and especially when being implemented by
well-known for it's proprietary "cripple-everything-else" extension creep
Microsoft.
It has a twist in authrization_code grant flow for "mobile" apps, where bearer
token refresh can be performed without having to provide client_secret. Client
app must be marked as "mobile" in [DevCenter](https://manage.dev.live.com/) for
that to work.
There's also totally LiveConnect-specific "Sign-In" auth flow.
Access tokens for SkyDrive scopes (plus wl.offline) seem to be issued with ttl
of one hour.

Permissions are set per-path, are inherited for the created objects and
**cannot** be changed through the API, only through the Web UI (or maybe
proprietary windows interfaces as well).

Accessible to everyone URL links (of different types - embedded, read-only,
read-write, preauthenticated) to any restricted-access object (that is reachable
through the API) can be provided in "preauthenticated" form, a bit like in
tahoe-lafs, but probably without the actual crypto keys embedded in them (not
much point as they're kept server-side along with the files anyway).

All but a few default paths (like "my\_documents") are accessed by file/folder
IDs.
All IDs seem to be in the form of
"{obj\_type}.{uid\_lowercase}.{uid\_uppercase}!{obj\_number}", where "obj\_type"
is a type of an object (e.g. "file", "folder", etc), "uid\_*" is some 8-byte
hex-encoded value, constant for all files/folders of the user, and "obj\_number"
is an integer value counting up from one for each uploaded file.

UI-visible names come on top of these IDs as metadata (so "rename" is
essentially a metadata "name" field update).
Aforementioned "default paths" (like "my_documents") don't seem to work reliably
with copy and move methods, unless resolved to folder_id proper.

There are some handy special API URLs for stuff like quota and a list of recent
changes.

Errors can be returned for most ops, encoded as JSON in responses and have a
human-readable "code" (like "resource_quota_exceeded") and descriptive
"message".

Files have a lot of metadata attached to them, parsed from their contents (exif
data for photos, office documents metadata, etc).
API allows to request image-previews of an items, links to which are also
available in file (object) metadata.

Actual fetching of files seem to be done through
https://public.bay.livefilestore.com, but TLS there doesn't work with
curl or python "requests" module at the moment, only with browsers.
Problem seem to be broken TLS implementation on the IIS server - it chokes if
client advertise TLS 1.2 in "Client Hello" packet (e.g. "openssl s_client
-showcerts -connect public.bay.livefilestore.com:443") and works if client only
advertises TLS 1.0 support ("openssl s_client -tls1 -showcerts -connect
public.bay.livefilestore.com:443").
Issue is known and generic workaround is documented as such in openssl project
changelog.
Newer "requests" module seem to have workaround for the issue implemented
(0.14.0 seem to work, 0.10.8 does not).

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
