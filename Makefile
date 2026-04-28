.PHONY: all deps lib python test clean fmt

all: deps lib python

deps:
	@if [ ! -f external/pcre2/build/lib/libpcre2-8.a ]; then \
		bash scripts/fetch_deps.sh; \
	fi

lib: deps
	$(MAKE) -C lib

python: lib
	$(MAKE) -C python

test:
	$(MAKE) -C lib test
	$(MAKE) -C python test

clean:
	$(MAKE) -C lib clean
	$(MAKE) -C python clean
	$(MAKE) -C web clean
	rm -rf python/*.egg-info
	rm -rf python/hexlock/__pycache__
	rm -rf dist/
	rm -rf build/

fmt:
	find lib -name '*.c' -o -name '*.h' | xargs clang-format -i
	cd python && black .
