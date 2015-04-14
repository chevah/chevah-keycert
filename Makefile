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
	

local_env:
	@if [ ! -d "build/venv" ]; then virtualenv build/venv; fi
	@$(BASE_PATH)/pip install -U pip


deps: local_env deps_base


deps_base:
	@$(BASE_PATH)/pip install \
		--extra-index-url ${EXTRA_PYPI_INDEX}\
		--trusted-host chevah.com \
		-e .[dev]


clean:
	@rm -rf build


test:
	@$(BASE_PATH)/python setup.py test -q
	@echo "See HTML coverate in build/cover"
	@$(BASE_PATH)/coverage html -d build/cover/


ci_deps: ci_env deps_base


ci_env:
	@mkdir -p build
	./paver.sh distributable_python build/venv


ci_test:
	ifeq "$(TEST_TYPE)" "os-independent"
	    @$(BASE_PATH)/pyflakes chevah
	    @$(BASE_PATH)/pep8 chevah
	else
	    @$(BASE_PATH)/nosetests
	endif
