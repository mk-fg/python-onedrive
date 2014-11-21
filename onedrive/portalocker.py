#-*- coding: utf-8 -*-

import os


if os.name == 'nt':
	# Needs pywin32 to work on Windows (NT, 2K, XP, _not_ /95 or /98)
	try: import win32con, win32file, pywintypes
	except ImportError as err:
		raise ImportError( 'Failed to import pywin32'
			' extensions (make sure pywin32 is installed correctly) - {}'.format(err) )

	LOCK_EX = win32con.LOCKFILE_EXCLUSIVE_LOCK
	LOCK_SH = 0 # the default
	LOCK_NB = win32con.LOCKFILE_FAIL_IMMEDIATELY
	__overlapped = pywintypes.OVERLAPPED()

	def lock(file, flags):
		hfile = win32file._get_osfhandle(file.fileno())
		win32file.LockFileEx(hfile, flags, 0, 0x7FFFFFFF, __overlapped)

	def unlock(file):
		hfile = win32file._get_osfhandle(file.fileno())
		win32file.UnlockFileEx(hfile, 0, 0x7FFFFFFF, __overlapped)


elif os.name == 'posix':
	from fcntl import lockf, LOCK_EX, LOCK_SH, LOCK_NB, LOCK_UN

	def lock(file, flags):
		lockf(file, flags)

	def unlock(file):
		lockf(file, LOCK_UN)


else:
	raise RuntimeError('PortaLocker only defined for nt and posix platforms')
