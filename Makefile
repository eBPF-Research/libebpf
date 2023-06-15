.PHONY: install coverage test docs help build clean build-arm run-arm run-arm64 build-arm64 build-arm32
.DEFAULT_GOAL := help

define BROWSER_PYSCRIPT
import os, webbrowser, sys

try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"
INSTALL_LOCATION := ~/.local

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

test: ## run tests quickly with ctest
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Dlibebpf_ENABLE_UNIT_TESTING=1 -DCMAKE_BUILD_TYPE="Release"
	cmake --build build --config Release
	cd build/ && ctest -C Release -VV

coverage: ## check code coverage quickly GCC
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -Dlibebpf_ENABLE_CODE_COVERAGE=1
	cmake --build build --config Release
	cd build/ && ctest -C Release -VV
	cd .. && (bash -c "find . -type f -name '*.gcno' -exec gcov -pb {} +" || true)

docs: ## generate Doxygen HTML documentation, including API docs
	rm -rf docs/
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION) -DProject_ENABLE_DOXYGEN=1
	cmake --build build --config Release
	cmake --build build --target doxygen-docs
	$(BROWSER) docs/html/index.html

build: build-x86 build-arm32 build-arm64

build-x86: ## build the package
	rm -rf build/
	cmake -Bbuild
	cmake --build build --config Debug

build-arm32: ## build the package on arm32
	rm -rf build/
	cmake -Bbuild -DCMAKE_TOOLCHAIN_FILE=cmake/arm-toolchain.cmake -DARCH=arm
	cmake --build build --config Debug

run-arm32: build-arm32 ## run the binary on arm32 qemu
	qemu-arm -L /usr/arm-linux-gnueabihf/  build/bin/Debug/libebpf

build-arm64: ## build the package on arm64
	rm -rf build/
	cmake -Bbuild -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-toolchain.cmake -DARCH=aarch64
	cmake --build build --config Debug

run-arm64: build-arm64 ## run the binary on arm32 qemu
	qemu-aarch64 -L /usr/aarch64-linux-gnu/ build/bin/Debug/libebpf

install: ## install the package to the `INSTALL_LOCATION`
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION)
	cmake --build build --config Release
	cmake --build build --target install --config Release

format: ## format the project sources
	rm -rf build/
	cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION)
	cmake --build build --target clang-format

clean: ## clean the project
	rm -rf build/
