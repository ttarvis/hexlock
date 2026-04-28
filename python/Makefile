.PHONY: all copy_lib test clean

UNAME := $(shell uname -s)
ifeq ($(UNAME), Darwin)
    DYLIB := libhexlock.dylib
else
    DYLIB := libhexlock.so
endif

DYLIB_SRC := ../lib/$(DYLIB)
DYLIB_DST := hexlock/_lib/$(DYLIB)

all: $(DYLIB_DST)

# Dependency-tracked copy for local dev — only runs if lib was rebuilt
$(DYLIB_DST): $(DYLIB_SRC)
	mkdir -p hexlock/_lib
	cp $(DYLIB_SRC) $(DYLIB_DST)

# Unconditional copy for CI — called explicitly by cibuildwheel
copy_lib:
	mkdir -p hexlock/_lib
	cp $(DYLIB_SRC) $(DYLIB_DST)

test: all
	python3 -m pytest tests/ -v

clean:
	rm -f $(DYLIB_DST)
