CC = clang

CFLAGS += -march=native
CFLAGS += -O3 -ftree-vectorize -fvectorize -ffast-math -fno-finite-math-only
CFLAGS += -fPIC -Iinclude -Iinclude/memscan

LDFLAGS += -shared -lelf -lpthread -lm

TARGET  = libmemscan.so
SRCDIR  = src
SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
# Just for fun.