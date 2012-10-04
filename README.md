python-skydrive
----------------------------------------

Python and command-line interface for [SkyDrive API (version
5.0)](http://msdn.microsoft.com/en-us/library/live/hh826521).

This module allows to access data on Microsoft SkyDrive cloud storage from
python code, abstracting authentication, http requests and response processing
to a simple python methods.

Module also comes with command-line tool to conveniently browse and manipulate
SkyDrive contents from interactive shell or scripts.



Command-line usage
----------------------------------------

SkyDrive API requires to register an application in
[DevCenter](https://manage.dev.live.com/), providing you with client_id and
client_secret strings, used for authentication.

I can't provide some static ones because according to LiveConnect ToS "You are
solely and entirely responsible for all uses of Live Connect occurring under
your Client ID" (also see notes below), and I can't just vouch for every
module/tool user like that.

App registration in DevCenter is really straightforward and shouldn't take more
than a few clicks.
Be sure to check the "mobile client app" box under "API settings".

After that, create "~/.lcrc" file ([YAML](https://en.wikipedia.org/wiki/YAML))
with the contents like these:

	client:
	  id: 00000000620A3E4A
	  secret: gndrjIOLWYLkOPl0QhWIliQcg-MG1SRN

(use "id" and "secret" acquired in the app registration step above, indent these
lines with spaces)

Then you need to perform OAuth 2.0 authorization dance by running the
`skydrive-cli auth` command and following printed instructions (visit printed
URL, authorize, click "Allow", paste last URL back into terminal).
This will get you authorization_code (which will be stored in ~/.lcrc) to use
the API as a user you've logged-in as there. Repeat this step to authorize with
a different account, if necessary.

Then just type whatever commands you want to (and don't forget `skydrive-cli
--help`):

	% skydrive-cli tree

	SkyDrive:
		Documents:
			README.txt: file
		Pics:
			image1.jpg: photo
			image2.jpg: photo

	% skydrive-cli get Pics/image1.jpg > downloaded_image1.jpg
	% skydrive-cli put downloaded_image1.jpg
	% skydrive-cli ls

	- Documents
	- Pics
	- downloaded_image1.jpg

	% skydrive-cli quota

	free: 24.9G
	quota: 25.0G

	% skydrive-cli link -t embed downloaded_image1.jpg

	embed_html: <iframe src="https://skydrive.live.com/embed?cid=..."
		width="98" height="120" frameborder="0" scrolling="no"></iframe>

	% skydrive-cli rm downloaded_image1.jpg
	% skydrive-cli rm -h

	usage: skydrive-cli rm [-h] object [object ...]

	positional arguments:
	  object      Object(s) to remove.

	optional arguments:
	  -h, --help  show this help message and exit

	% skydrive-cli -h

	...

Most commands should be self-descriptive, but use "--help" when they aren't.

Note that objects specified on the command-line are implicitly resolved as
human-readable paths (which are basically metadata) unless they look like an id.
This might be undesirable from performance perspective (extra requests) and
might be undesirable if non-unique "name" attributes of objects in the same
parent folder are used.
Use "-p" or "-i" ("--path" / "--id") switches to control this explicitly.
See LiveConnect docs or notes section below for more info on how these work.



Module usage
----------------------------------------

[doc/api.md](https://github.com/mk-fg/python-skydrive/blob/master/doc/api.md)
file contains auto-generated (from code) API docs.

API code is split between three classes:

* HTTP wrapper - SkyDriveHTTPClient
* Authentication methods - SkyDriveAuth
* Unbiased and simple wrappers around HTTP calls - SkyDriveAPIWrapper, each one
	returning decoded HTTP response (i.e. whatever request method in
	SkyDriveHTTPClient returns).
* Biased convenience methods - SkyDriveAPI

Such separation allowed to reuse SkyDriveAPIWrapper class to wrap async
(returning "Deferred" objects instead of data) in
[txSkyDrive](https://github.com/mk-fg/txskydrive) just by overriding "request"
method from SkyDriveHTTPClient.

See also
[skydrive/cli_tool.py](https://github.com/mk-fg/python-skydrive/blob/master/skydrive/cli_tool.py)
for real-world API usage examples.



Installation
----------------------------------------

It's a regular package for Python 2.7 (not 3.X).

Using [pip](http://pip-installer.org/) is the best way:

	% pip install 'python-skydrive[standalone]'

If you don't have it, use:

	% easy_install pip
	% pip install 'python-skydrive[standalone]'

Alternatively ([see
also](http://www.pip-installer.org/en/latest/installing.html)):

	% curl https://raw.github.com/pypa/pip/master/contrib/get-pip.py | python
	% pip install 'python-skydrive[standalone]'

Or, if you absolutely must:

	% easy_install python-skydrive requests

But, you really shouldn't do that.

Current-git version can be installed like this:

	% pip install 'git+https://github.com/mk-fg/python-skydrive.git#egg=python-skydrive'

"standalone" option above enables dependency on "requests" module, which is used
as default HTTP client lib. If the plan is to extend or override that, flag can
be dropped.

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

* (unless your plan is to override that)
	[requests](http://docs.python-requests.org/en/latest/)

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

UI-visible names come on top of these IDs as metadata, so "rename" is
essentially a metadata "name" field update and two files/folders with the same
"name" can co-exist in the same parent folder, though uploading a file defaults
to overwriting file with same "name" (disableable).

Aforementioned "default paths" (like "my_documents") don't seem to work reliably
with copy and move methods, unless resolved to folder_id proper.

There's a "Recycle Bin" path in web interface, which I don't recall seeing any
way to access, which keeps all removed files (for some limited time,
presumably). Files removed through the API end up there as well.

There are some handy special SkyDrive-related API URLs for stuff like quota,
list of recent changes and a list of shared-with-me objects.

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

Errors can be returned for most ops, encoded as JSON in responses and have a
human-readable "code" (like "resource_quota_exceeded") and descriptive
"message".

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
