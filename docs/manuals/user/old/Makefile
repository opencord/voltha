#
# Copyright 2016 the original author or authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ifeq ($(VOLTHA_BASE)_set,_set)
$(error To get started, please source the env.sh file)
endif

default: build

GENERATED_SVG_FILES := \
	pon-requirements/reference-inband.svg \
	pon-requirements/reference-internal.svg \
	pon-requirements/olt-states.svg

build: checkdiag $(GENERATED_SVG_FILES)
	@echo "Building drawings"

%.svg: %.block
	blockdiag -T svg -o $@ $<

%.svg: %.seq
	seqdiag -T svg -o $@ $<

clean:
	rm -f $(GENERATED_SVG_FILES)

checkdiag:
	@if ! blockdiag --version > /dev/null; then \
	  echo "Installing blockdiag..."; \
	  pip install blockdiag; \
	fi
	@if ! seqdiag --version > /dev/null; then \
	  echo "Installing seqdiag..."; \
	  pip install seqdiag; \
	fi
	@echo "Tools ready"

