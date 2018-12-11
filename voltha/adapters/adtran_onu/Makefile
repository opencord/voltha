THIS_MAKEFILE      := $(abspath $(MAKEFILE_LIST) )
WORKING_DIR        := $(dir $(THIS_MAKEFILE) )
ADAPTERS_DIR       := $(dir $(patsubst %/,%,$(WORKING_DIR)))
VOLTHA_DIR         := $(dir $(patsubst %/,%,$(ADAPTERS_DIR)))

VENVDIR=$(WORKING_DIR)venv
TESTDIR=$(WORKING_DIR)test

ADD_TO_PYTHONPATH := export PYTHONPATH=$(PYTHONPATH):$(VOLTHA_DIR)/protos/third_party;
IN_VENV=. '$(VENVDIR)/bin/activate';

PROFILING=--profile-svg
DOT := $(shell command -v dot 2> /dev/null)
ifndef DOT
$(warning "dot is not available please install graphviz")
PROFILING=
endif

RUN_PYTEST=$(IN_VENV) $(ADD_TO_PYTHONPATH) py.test -vvlx $(PROFILING) --cov=$(WORKING_DIR) --cov-report term-missing --cov-report html

$(VENVDIR):
	@virtualenv -p python2 $(VENVDIR)
	@virtualenv -p python2 --relocatable $(VENVDIR)

.PHONY: create-venv
create-venv: $(VENVDIR)

.PHONY: test
test: create-venv
	@$(IN_VENV) command -v py.test > /dev/null 2>&1 || `echo >&2 "'make requirements' first. Aborting."; exit 1;`
	@rm -rf $(TESTDIR)/__pycache__
	@cd $(WORKING_DIR) && $(RUN_PYTEST) $(TESTDIR)

.PHONY: requirements
requirements: create-venv
	@$(IN_VENV) pip install --upgrade -r test_requirements.txt
