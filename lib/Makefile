CC      ?= gcc
AR      ?= ar
ARFLAGS ?= rcs

PCRE2_LIB := ../external/pcre2/build/lib/libpcre2-8.a

SRCS := $(wildcard regex/*.c) $(wildcard fpe/*.c) $(wildcard router/*.c) $(wildcard tokenizer/*.c)
OBJS := $(SRCS:.c=.o)
LIB  := libhexlock.a

DEPS := $(OBJS:.o=.d)
-include $(DEPS)

# Platform-specific shared library name and flags
UNAME := $(shell uname -s)
ifeq ($(UNAME), Darwin)
    DYLIB        := libhexlock.dylib
    SHARED_FLAGS := -dynamiclib
else
    DYLIB        := libhexlock.so
    SHARED_FLAGS := -shared
endif

# ARCH_FLAGS can be injected by the caller (e.g. cibuildwheel)
# e.g. make lib ARCH_FLAGS="-arch x86_64"
ARCH_FLAGS ?=

CFLAGS ?= -Wall -Wextra -O2 -fPIC \
           -Iinclude -Ifpe -Iregex -Itokenizer \
           -I../external/pcre2/build/include

.PHONY: all test clean

all: $(LIB) $(DYLIB)

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(DYLIB): $(OBJS)
	$(CC) $(SHARED_FLAGS) $(ARCH_FLAGS) -o $@ $^ $(PCRE2_LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(ARCH_FLAGS) -MMD -MP -c $< -o $@

test: $(LIB)
	$(CC) $(CFLAGS) -o _test_runner tests/main.c $(LIB) $(PCRE2_LIB) && ./_test_runner

clean:
	rm -f $(OBJS) $(LIB) $(DYLIB) _test_runner $(DEPS)
