# libelf 本地编译 Makefile
CC      := gcc
CFLAGS  := -O2 -fPIC -Wall -Wno-unused-parameter -Wno-implicit-function-declaration
LDFLAGS := -shared
TARGET  := libelf.so

SRC_DIR := src
INC_DIR := include
OBJ_DIR := obj

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

# ★ 关键：同时添加两个包含路径
INCLUDES := -I$(INC_DIR) -I$(INC_DIR)/libelf

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)