#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import itertools as it, operator as op, functools as ft
import os, sys, re


class FormatError(Exception): pass


def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='Convert sphinx-produced autodoc.apidoc text to markdown.')
	parser.add_argument('src', nargs='?', help='Source file (default: use stdin).')
	optz = parser.parse_args()

	src = open(optz.src) if optz.src else sys.stdin
	dst = sys.stdout

	py_name = r'[\w_\d]+'
	out = ft.partial(print, file=dst)

	st_attrdoc = 0

	for line in src:
		ls = line.strip()
		if not ls: # blank line
			out(line, end='')
			continue

		line_indent = re.search(r'^( +)', line)
		if not line_indent: line_indent = 0
		else:
			line_indent = len(line_indent.group(1))
			if line_indent % 3: raise FormatError('Weird indent size: {}'.format(line_indent))
			line_indent = line_indent / 3

		lp = line.split()
		lse = ls.replace('_', r'\_').replace('*', r'\*')
		for url in re.findall(r'\b\w+://\S+', lse):
			lse = lse.replace(url, url.replace(r'\_', '_'))
		lse = re.sub(r'\bu([\'"])', r'\1', lse)

		st_attrdoc_reset = True
		if not line_indent:
			if len(lp) > 2 and lp[0] == lp[1]:
				if lp[0] in ('exception', 'class'): # class, exception
					out('* **{}**'.format(' '.join(lse.split()[1:])))

			else:
				raise FormatError('Unhandled: {!r}'.format(line))

		elif line_indent == 1:
			if re.search(r'^{}\('.format(py_name), ls): # function
				out('\n'*1, end='')
				out('{}* {}'.format(' '*4, lse))
				st_attrdoc, st_attrdoc_reset = 8, False
			elif re.search(r'^{}\s+=\s+'.format(py_name), ls): # attribute
				out('{}* {}'.format(' '*4, lse))
				st_attrdoc, st_attrdoc_reset = 8, False
			elif lp[0] == 'Bases:': # class bases
				out('{}{}'.format(' '*4, lse))
				st_attrdoc, st_attrdoc_reset = 4, False
			else: out('{}{}'.format(' '*4, ls)) # class docstring

		else: # description line
			if ls[0] in '-*': line = '\\' + line.lstrip()
			out('{}{}'.format(' '*st_attrdoc, line.lstrip()), end='')
			st_attrdoc_reset = False

		if st_attrdoc and st_attrdoc_reset: st_attrdoc = 0


if __name__ == '__main__': main()
