#
# Makefile for Chevah KeyCert project.
#
EXTRA_PYPI_INDEX='http://chevah.com/pypi/simple'
UNAME=`uname`
ifeq "$(UNAME)" "mingw"
       BASE_PATH='build/venv/Scripts/'
else
       BASE_PATH='build/venv/bin/'
endif

all: test
	

env:
	@if [ ! -d "build/venv" ]; then virtualenv build/venv; fi


deps: env
	@$(BASE_PATH)/pip install \
		--extra-index-url ${EXTRA_PYPI_INDEX}\
		--download-cache __pycache__\
		-e .[dev]


clean:
	@rm -rf build


dist-clean: clean
	@rm -rf __pycache__


lint:
	@echo -n "Running linter..."
	@$(BASE_PATH)/pocketlint chevah/keycert/
	@echo "All good."

test:
	@$(BASE_PATH)/nosetests --with-coverage --cover-package=chevah.keycert --cover-erase --cover-test
	@echo -n "Running linter..."
	@$(BASE_PATH)/pyflakes chevah/keycert/
	@$(BASE_PATH)/pep8 --hang-closing chevah/keycert/
	@echo "All good."
