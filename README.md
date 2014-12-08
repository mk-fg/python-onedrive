python-onedrive
----------------------------------------

**Compatibility note:** if setup.py, requirements.txt and/or package depends on
"skydrive.api_v5" module from python-skydrive (pre-rename, now it's
"onedrive.api_v5"), "python-onedrive==14.04.0" package (with old API) can be
used in its place - i.e. just replace any "python-skydrive" pkg-spec with that.

Python and command-line interface for
[OneDrive REST API (version 5.0)](http://msdn.microsoft.com/library/dn659752.aspx)
(formerly known as SkyDrive).

This module allows to access data on Microsoft OneDrive cloud storage from
python code, abstracting authentication, http requests and response processing
to a simple python methods.

Module also comes with command-line tool to conveniently browse and manipulate
OneDrive contents from interactive shell or scripts.

Thanks to AntonioChen for implementing windows and unicode support (see
[#3](https://github.com/mk-fg/python-onedrive/pull/3)).

Service was called SkyDrive prior to 2014-02-19, when it got renamed to OneDrive.
This package similarly renamed from python-skydrive to python-onedrive.

Be sure to read "Known Issues and Limitations" section below before use, to
avoid any potentially nasty surprises.



Command-line usage
----------------------------------------

OneDrive API requires to register an application in
[DevCenter](https://dev.live.com/), providing you with client_id and
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

(use "id" and "secret" acquired in the app registration step above, *indent these
lines with spaces* - indenting with tabs is not allowed in YAML)

Then you need to perform OAuth 2.0 authorization dance by running the
`onedrive-cli auth` command and following printed instructions (visit printed
URL, authorize, click "Allow", paste last URL back into terminal).
This will get you authorization_code (which will be stored in ~/.lcrc) to use
the API as a user you've logged-in as there. Repeat this step to authorize with
a different account, if necessary.

Then just type whatever commands you want to (and don't forget `onedrive-cli
--help`):

	% onedrive-cli tree

	OneDrive:
		Documents:
			README.txt: file
		Pics:
			image1.jpg: photo
			image2.jpg: photo

	% onedrive-cli get Pics/image1.jpg downloaded_image1.jpg
	% onedrive-cli put downloaded_image1.jpg
	% onedrive-cli ls

	- Documents
	- Pics
	- downloaded_image1.jpg

	% onedrive-cli quota

	free: 24.9G
	quota: 25.0G

	% onedrive-cli link -t embed downloaded_image1.jpg

	embed_html: <iframe src="https://onedrive.live.com/embed?cid=..."
		width="98" height="120" frameborder="0" scrolling="no"></iframe>

	% onedrive-cli rm downloaded_image1.jpg
	% onedrive-cli rm -h

	usage: onedrive-cli rm [-h] object [object ...]

	positional arguments:
	  object      Object(s) to remove.

	optional arguments:
	  -h, --help  show this help message and exit

	% onedrive-cli -h

	...

Most commands should be self-descriptive, but use "--help" when they aren't.

Note that objects specified on the command-line are implicitly resolved as
human-readable paths (which are basically metadata) unless they look like an id.
This might be undesirable from performance perspective (extra requests) and
might be undesirable if non-unique "name" attributes of objects in the same
parent folder are used.
Use "-p" or "-i" ("--path" / "--id") switches to control this explicitly.
See LiveConnect docs or notes section below for more info on how these work.

If you get HTTP error 400 right after or during "auth" command, read
[this comment on #4](https://github.com/mk-fg/python-onedrive/issues/4#issuecomment-18233153)
(maybe with some context).



Known Issues and Limitations
----------------------------------------

* Uploading of files larger than ~100 MiB via single POST/PUT request is
	apparently not supported by OneDrive API - see
	[#16](https://github.com/mk-fg/python-onedrive/issues/16) for details.

	Workaround in place is to fallback to (experimental at the moment of writing - 2014-11-23)
	[BITS API](https://gist.github.com/rgregg/37ba8929768a62131e85) for larger files,
	but it has a few issues, mentioned below.

* Be very careful using this module on Windows - it's very poorly tested there,
	which is apparent from several serious issues that's been reported - see commit
	d31fb51 and [this report](https://github.com/kennethreitz/requests/issues/2039),
	for instance.

	Not sure how useful might be explicitly breaking things for WIndows (to avoid
	users having such issues from the start), especially since it's extra work to
	remove functionality that was contributed by someone else, who apparently
	found it useful to have here.

* Some proprietary formats, like "OneNote notebook" just can't be accessed
	([see #2](https://github.com/mk-fg/python-onedrive/issues/2)).
	OneDrive doesn't allow GET requests for these things and they're also special
	exceptions to [other API methods](http://msdn.microsoft.com/en-us/library/live/hh243648.aspx#file),
	no idea what can be done there.

* It's been reported (#17) that [Onedrive for Business](https://onedrive.live.com/about/en-us/business/)
	is not supported. It seem to have different
	[SharePoint 2013 API](http://msdn.microsoft.com/en-us/library/fp142380%28v=office.15%29.aspx).

* Be very careful when relying on [BITS API](https://gist.github.com/rgregg/37ba8929768a62131e85),
	as it seem to be in very experimental state for regular OneDrive service, with
	only info I've seen on it (in relation to OneDrive, and not other MS services)
	being that linked gist file (actually pointed out to me by @bobobo1618 in #34).

	Some issues with it (at the moment of writing this - 2014-12-08) are mentioned
	in [issue-34](https://github.com/mk-fg/python-onedrive/issues/34)
	and [issue-39](https://github.com/mk-fg/python-onedrive/issues/39).


Module usage
----------------------------------------

[doc/api.md](https://github.com/mk-fg/python-onedrive/blob/master/doc/api.md)
file contains auto-generated (from code) API docs.

API code is split between three classes:

* HTTP wrapper - OneDriveHTTPClient
* Authentication methods - OneDriveAuth
* Unbiased and simple wrappers around HTTP calls - OneDriveAPIWrapper, each one
	returning decoded HTTP response (i.e. whatever request method in
	OneDriveHTTPClient returns).
* Biased convenience methods - OneDriveAPI

Such separation allowed to reuse OneDriveAPIWrapper class to wrap async
(returning "Deferred" objects instead of data) in
[txOneDrive](https://github.com/mk-fg/txonedrive) just by overriding "request"
method from OneDriveHTTPClient.

See also
[onedrive/cli_tool.py](https://github.com/mk-fg/python-onedrive/blob/master/onedrive/cli_tool.py)
for real-world API usage examples.



Installation
----------------------------------------

It's a regular package for Python 2.7 (not 3.X).

Using [pip](http://pip-installer.org/) (see also
) is the best way:

	% pip install 'python-onedrive[standalone]'

If you don't have it, use:

	% easy_install pip
	% pip install 'python-onedrive[standalone]'

Alternatively (see also
[pip2014.com](http://pip2014.com/) and
[install guide](http://www.pip-installer.org/en/latest/installing.html)):

	% curl https://raw.github.com/pypa/pip/master/contrib/get-pip.py | python
	% pip install 'python-onedrive[standalone]'

Or, if you absolutely must:

	% easy_install python-onedrive requests

But, you really shouldn't do that.

Current-git version can be installed like this:

	% pip install 'git+https://github.com/mk-fg/python-onedrive.git#egg=python-onedrive'

"standalone" option above enables dependency on "requests" module, which is used
as default HTTP client lib. If the plan is to extend or override that, flag can
be dropped.

Note that to install stuff in system-wide PATH and site-packages, elevated
privileges are often required.
Use "install --user",
[~/.pydistutils.cfg](http://docs.python.org/install/index.html#distutils-configuration-files)
or [virtualenv](http://pypi.python.org/pypi/virtualenv) to do unprivileged
installs into custom paths.

Alternatively, `./onedrive-cli` tool can be run right from the checkout tree
without any installation, if that's the only thing you need there.


### Requirements

* [Python 2.7 (not 3.X)](http://python.org/)

* (unless your plan is to override that)
	[requests](http://docs.python-requests.org/en/latest/) - versions 0.14.0 or
	higher are strongly recommended - ideally 1.0.0+ (see "Known Issues" section
	below for rationale)

* (optional, recommended) [PyYAML](http://pyyaml.org) - required for CLI tool
	and optional persistent-state ("conf") module only.

* (only on windows) [pywin32](http://sourceforge.net/projects/pywin32/) - for
	CLI tool (used to lock configuration file on changes) and optional conf module
	only.

* (optional) [chardet](http://pypi.python.org/pypi/chardet) - used to detect
	encoding (utf-8, gbk, koi8-r, etc) of the command-line arguments to support
	workng with non-ascii (e.g. cyrillic, chinese) names, if it's not specified
	explicitly.



LiveConnect/OneDrive API (v5.0) notes
----------------------------------------

Important: these details can (naturally) go obsolete, especially if timestamp of
this doc is older than the one of the API docs, in which case please open an
Issue pointing to the inconsistency.

It's quite a conventional REST API with JSON encoding of structured data, like
pretty much every other trendy modern API, say, github.

Authentication is ["OAuth 2.0"](http://msdn.microsoft.com/en-us/library/dn659750.aspx),
which is quite ambigous all by itself, and especially when being implemented by
well-known for it's proprietary "cripple-everything-else" extension creep
Microsoft.
It has a twist in authrization_code grant flow for "mobile" apps, where bearer
token refresh can be performed without having to provide client_secret. Client
app must be marked as "mobile" in [DevCenter](https://dev.live.com/) for
that to work.
There's also totally LiveConnect-specific "Sign-In" auth flow.
Access tokens for OneDrive scopes (plus wl.offline) seem to be issued with ttl
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

There are some handy special OneDrive-related API URLs for stuff like quota,
list of recent changes and a list of shared-with-me objects.

Files have a lot of metadata attached to them, parsed from their contents (exif
data for photos, office documents metadata, etc).
API allows to request image-previews of an items, links to which are also
available in file (object) metadata.

There was an issue with public.bay.livefilestore.com hosts (to which actual file
store/retrieve requests get redirected) not working with clients advertising
TLS -1.2 (see issue-1 on github), but it seem to be gone by now (2014-11-21).

File uploads can either use PUT or POST requests, but former (PUT) *must* use
"Transfer-Encoding: chunked" or requests just hang and get closed by the server.
For more info on this quirk, see github issue #30.

Errors can be returned for most ops, encoded as JSON in responses and have a
human-readable "code" (like "resource_quota_exceeded") and descriptive
"message".

According to "OneDrive interaction guidelines", it is discouraged (though not
explicitly prohibited) to upload files in non-conventional formats that aren't
useable to other apps (under "Use OneDrive for the things that it’s good at"):

	To support this principle, the Live Connect APIs limit the set of file formats
	that apps can upload to OneDrive.

ToS for LiveConnect APIs is kinda weird, having unclear (at least to layman like
me) stuff like this:

* You may only use the Live SDK and Live Connect APIs to create software.

	Seem to imply that APIs shouldn't be used in hardware, but I fail to see why
	it can't also be interpreted as "only create software, not just use it to
	get/store stuff".

* You are solely and entirely responsible for all uses of Live Connect occurring
	under your Client ID.

	So either you take the blame for every potential user or go make all users
	register their own app? Hopefully I've misinterpreted that one.

After SkyDrive -> OneDrive rename (on 2014-02-19), API remained the same, with
same URLs, same "me/skydrive" root, and API docs still seem to refer to the
service as SkyDrive.

For more robust and fault-tolerant uploads, OneDrive seem to support BITS API,
allowing to upload each individual file via several http requests, with some
(non-overlapping) byte-range in each.
More details/discussion on this API can be found in
[issue-34 on github](https://github.com/mk-fg/python-onedrive/issues/34)
and [this github gist](https://gist.github.com/rgregg/37ba8929768a62131e85).
As of now (2014-11-21), this is "preliminary documentation and is subject to
change".
