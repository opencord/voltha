THIS_MAKEFILE      := $(abspath $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)))
WORKING_DIR        := $(dir $(THIS_MAKEFILE) )
ADAPTER_NAME       := $(notdir $(patsubst %/,%,$(WORKING_DIR)))
ADAPTERS_DIR       := $(dir $(patsubst %/,%,$(WORKING_DIR)))
VOLTHA_DIR         := $(dir $(patsubst %/,%,$(ADAPTERS_DIR)))
export VOLTHA_BASE := $(VOLTHA_DIR)../
GIT_DIR            := $(dir $(patsubst %/,%,$(VOLTHA_DIR))).git

OPENOLT_DIR        := $(ADAPTERS_DIR)openolt
OPENOLT_PROTO      := $(shell find $(OPENOLT_DIR)/protos/ -name '*.proto')
OPENOLT_PB2        := $(patsubst %.proto,%_pb2.py,$(OPENOLT_PROTO))

VOLTHA_PROTO       := $(shell find $(VOLTHA_DIR)protos -name '*.proto')
VOLTHA_PB2         := $(patsubst %.proto,%_pb2.py,$(VOLTHA_PROTO))

VENVDIR             =$(VOLTHA_BASE)venv-$(shell uname -s | tr '[:upper:]' '[:lower:]')
TESTDIR             =$(WORKING_DIR)test

ifneq ($(VOLTHA_BUILD),docker)
IN_VENV            :=. '$(VENVDIR)/bin/activate';
TEST_REQ_INSTALLED := $(VENVDIR)/.$(ADAPTER_NAME)-test
GIT_COMMIT_MSG_BIN := $(GIT_DIR)/hooks/commit-msg
else
IN_VENV            :=
TEST_REQ_INSTALLED := $(WORKING_DIR)/.$(ADAPTER_NAME)-req-installed
GIT_COMMIT_MSG_BIN := $(WORKING_DIR)/.commit-msg
endif

RUN_PYTEST=$(IN_VENV) PYTHONPATH=$(VOLTHA_BASE):$(VOLTHA_DIR)protos/third_party py.test -vvlx

.PHONY: test
test: requirements hooks
	@rm -rf $(TESTDIR)/__pycache__
	@-find $(WORKING_DIR) -type f -name '*.pyc' -delete
	@cd $(WORKING_DIR); $(RUN_PYTEST) $(TESTDIR)
	@cd $(WORKING_DIR); coverage xml

.PHONY: clean
clean:
	@-rm -rf .coverage
	@-rm -rf htmlcov
	@-rm -rf *coverage.xml
	@-rm -rf junit*.xml
	@-rm -rf .pytest_cache
	@-find $(WORKING_DIR) -type f -name '*.pyc' -delete
	@-find $(VOLTHA_DIR)protos -type f -name '*_pb2.py' -delete
	@-find $(OPENOLT_DIR)/protos -type f -name '*_pb2.py' -delete

.PHONY: lint
lint: requirements
	@-$(IN_VENV) pylint `pwd`

.PHONY: create-venv
create-venv: $(VENVDIR)/.built


$(VENVDIR)/.built:
	cd $(VOLTHA_BASE); make venv

$(OPENOLT_PB2): %_pb2.py : %.proto
	@echo !-- Making $(@) because $< changed ---
	@cd $(OPENOLT_DIR); $(IN_VENV) $(MAKE)

$(VOLTHA_PB2): %_pb2.py : %.proto
	@echo !-- Making $(@) because $< changed ---
	@cd $(VOLTHA_DIR)/protos; $(IN_VENV) $(MAKE) third_party build

$(TEST_REQ_INSTALLED): $(WORKING_DIR)test_requirements.txt \
                       $(VOLTHA_BASE)requirements.txt
	@ $(IN_VENV) pip install --upgrade -r $(WORKING_DIR)test_requirements.txt
	@ if [ -f ${VENVDIR} ]; then $(VENV_BIN) -p python2 --relocatable ${VENVDIR}; fi
	@ uname -s > ${@};

.PHONY: requirements
requirements: create-venv $(OPENOLT_PB2) $(VOLTHA_PB2) $(TEST_REQ_INSTALLED)

.PHONY: hooks
hooks: $(GIT_COMMIT_MSG_BIN)
	@echo "Commit hooks installed"

$(GIT_COMMIT_MSG_BIN):
	@curl https://gerrit.opencord.org/tools/hooks/commit-msg > $(GIT_COMMIT_MSG_BIN)
	@chmod u+x $(GIT_COMMIT_MSG_BIN)
