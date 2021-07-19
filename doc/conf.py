import sys, os
from os.path import abspath, dirname, join


doc_root = dirname(__file__)
# autodoc_dump_rst = open(join(doc_root, 'autodoc.rst'), 'w')

os.chdir(doc_root)
sys.path.insert(0, abspath('..')) # for module itself
sys.path.append(abspath('.')) # for extensions

needs_sphinx = '1.1'
extensions = ['sphinx.ext.autodoc', 'sphinx_local_hooks']

master_doc = 'api'
pygments_style = 'sphinx'

source_suffix = '.rst'
# exclude_patterns = ['_build']
# templates_path = ['_templates']

autoclass_content = 'class'
autodoc_member_order = 'bysource'
autodoc_default_flags = ['members', 'undoc-members', 'show-inheritance']
