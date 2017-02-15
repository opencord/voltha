# Makefile to make it obvious what operations exist for this repo

GITBOOK := node_modules/.bin/gitbook

default: html

help:
	@echo "Available make targets:"
	@echo "  help             - Print this help"
	@echo "  serve            - Build gitbook static web pages and serve them locally"
	@echo "  html             - Build gitbook static pages under _book dir"
	@echo "  pdf              - Build gitbook pdf as book.pdf"
	@echo
	@echo "The following additional commands are used internally:"
	@echo "  check-gitbook    - Check gitbook if gitbook is installed"
	@echo "  install-gitbook  - Install the gitbook toolchain and plugins needed to build books"
	@echo "  prepare-gitbook  - Make sure gitbook plugins are installed"

check-gitbook:
	@echo "Checking 'gitbook' installation..."
	@if test -x $(GITBOOK) && $(GITBOOK) --version;\
	 then \
		echo "Good. You have gitbook installed.";\
	else \
		echo "No gitbook execuatble found. Please run:";\
		echo "";\
		echo "    make install-gitbook";\
		echo "";\
		echo "(You may be prompted for your password.)";\
	       	echo "";\
	fi

install-gitbook:
	@echo "Installing gitbook (may prompt for your password)..."
	npm install
	$(GITBOOK) install

prepare-gitbook: check-gitbook
	@echo "Checking 'gitbook' installation and do what's needed"
	$(GITBOOK) init

serve: prepare-gitbook
	@echo "Continuous building and serving static web pages..."
	$(GITBOOK) serve

html: prepare-gitbook
	@echo "Building static web pages..."
	$(GITBOOK) build

pdf: prepare-gitbook
	@echo "Building PDF book..."
	$(GITBOOK) pdf . VolthaMissingManual.pdf

clean:
	rm -rf _book
	rm -rf VolthaMissingManual.pdf
