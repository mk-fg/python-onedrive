PROJECT_ROOT = ..

.PHONY: text clean

text:
	cd $(PROJECT_ROOT); python setup.py build; cd
	sphinx-build -b text . .
	./sphinx_text_to_md.py api.txt > api.md

clean:
	-rm -rf $(BUILDDIR)/*
