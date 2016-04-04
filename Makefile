#
# Makefile for Chevah KeyCert project.
#
EXTRA_PYPI_INDEX='http://pypi.chevah.com/simple'

ifeq "$(MSYSTEM)" "MINGW32"
       BASE_PATH='build/venv/Scripts'
       PYTHON='build/venv/python.exe'
else
       BASE_PATH='build/venv/bin'
       PYTHON='build/venv/bin/python'
endif

BUILDBOT_TRY=$(BASE_PATH)/buildbot try \
		--connect=pb --username=chevah_buildbot --passwd=chevah_password \
		--master=build.chevah.com:10087 --vc=git


all: test
	

local_env:
	@if [ ! -d "build/venv" ]; then virtualenv2 build/venv; fi
	@$(BASE_PATH)/pip install -U pip


deps: local_env deps_base


deps_base:
	@$(BASE_PATH)/pip install \
		--extra-index-url ${EXTRA_PYPI_INDEX}\
		--trusted-host pypi.chevah.com \
		-e .[dev]


clean:
	@rm -rf build


test:
	@$(PYTHON) setup.py test -q
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


dev_deps:
	@$(BASE_PATH)/pip install buildbot

git_push:
	@echo 'Sending commited changes before sending patch'
	@git push

test_remote: git_push
ifeq "$(TARGET)" ""
	$(BUILDBOT_TRY) --get-builder-names | grep keycert
else
	$(BUILDBOT_TRY) -b $(TARGET)
endif

test_remote_with_clean: git_push
	$(BUILDBOT_TRY) -b $(TARGET) --properties=force_clean=yes

test_remote_with_wait: git_push
	$(BUILDBOT_TRY) -b $(TARGET) --wait
