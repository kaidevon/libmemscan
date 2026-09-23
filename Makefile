CC = clang

CFLAGS += -Iinclude -Iinclude/memscan -Iinclude/libelf -Ilibelf/include
CFLAGS += -march=native
CFLAGS += -O3 -ftree-vectorize -fvectorize -ffast-math -fno-finite-math-only
CFLAGS += -fPIC -D_GNU_SOURCE

LIBELF_DIR = libelf
LIBELF_SRCS = $(wildcard $(LIBELF_DIR)/src/*.c)
LIBELF_OBJS = $(LIBELF_SRCS:.c=.o)
LIBELF_TARGET = $(LIBELF_DIR)/libelf.so

LDFLAGS += -Wl,-rpath,'$$ORIGIN/lib' -Wl,-rpath,'$$ORIGIN'
LDFLAGS += -shared -L$(LIBELF_DIR) -lelf -lpthread -lm

TARGET  = libmemscan.so
SRCDIR  = src
SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(SRCS:.c=.o)

all: $(LIBELF_TARGET) $(TARGET)

# Build libelf.so from its source files
$(LIBELF_TARGET): $(LIBELF_OBJS)
	$(CC) -shared -o $@ $^

# libelf.so
$(TARGET): $(OBJS) $(LIBELF_TARGET)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(LIBELF_OBJS) $(LIBELF_TARGET)

.PHONY: all clean
# Just for fun.