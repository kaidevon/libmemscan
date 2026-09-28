CC = clang

CFLAGS += -Iinclude -Iinclude/vma
CFLAGS += -march=native
CFLAGS += -O3 -ftree-vectorize -fvectorize -ffast-math -fno-finite-math-only
CFLAGS += -fPIC -D_GNU_SOURCE

LDFLAGS += -Wl,-rpath,'$$ORIGIN/lib' -Wl,-rpath,'$$ORIGIN'
LDFLAGS += -shared -lpthread -lm

TARGET  = libmemscan.so
SRCDIR  = src
SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
# Just for fun.