#-*- coding: utf-8 -*-

import itertools as it, operator as op, functools as ft
from collections import Iterable
import types


from sphinx.ext.autodoc import Documenter

_autodoc_add_line = Documenter.add_line

@ft.wraps(_autodoc_add_line)
def autodoc_add_line(self, line, *argz, **kwz):
	tee = self.env.app.config.autodoc_dump_rst
	if tee:
		tee_line = self.indent + line
		if isinstance(tee, file): tee.write(tee_line + '\n')
		elif tee is True: print tee_line
		else:
			raise ValueError( 'Unrecognized'
				' value for "autodoc_dump_rst" option: {!r}'.format(tee) )
	return _autodoc_add_line(self, line, *argz, **kwz)

Documenter.add_line = autodoc_add_line


def process_docstring(app, what, name, obj, options, lines):
	if not lines: return

	i, ld = 0, dict(enumerate(lines)) # to allow arbitrary peeks
	i_max = max(ld)

	def process_line(i):
		line, i_next = ld[i], i + 1
		while i_next not in ld and i_next <= i_max: i_next += 1
		line_next = ld.get(i_next)

		if line_next and line_next[0] in u' \t': # tabbed continuation of the sentence
			ld[i] = u'{} {}'.format(line, line_next.strip())
			del ld[i_next]
			process_line(i)
		elif line.endswith(u'.') or (line_next and line_next[0].isupper()): ld[i+0.5] = u''

	for i in xrange(i_max + 1):
		if i not in ld: continue # was removed
		process_line(i)

	# Overwrite the list items inplace, extending the list if necessary
	for i, (k, line) in enumerate(sorted(ld.viewitems())):
		try: lines[i] = line
		except IndexError: lines.append(line)


def skip_override(app, what, name, obj, skip, options):
	if what == 'exception':
		return False if name == '__init__'\
			and isinstance(obj, types.UnboundMethodType) else True
	return skip

def setup(app):
	app.connect('autodoc-process-docstring', process_docstring)
	app.connect('autodoc-skip-member', skip_override)
	app.add_config_value('autodoc_dump_rst', None, True)
