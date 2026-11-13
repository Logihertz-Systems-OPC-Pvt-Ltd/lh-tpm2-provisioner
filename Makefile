CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -pedantic -Iinclude

SRCS = src/sha256_hmac.c \
       src/pcr_policy.c \
       src/seal_engine.c \
       src/json_parser.c \
       src/tpm2_auditor.c \
       src/exporters.c

OBJS = $(SRCS:.c=.o)
MAIN_OBJ = src/main.o
TEST_OBJ = tests/test_runner.o

TARGET = bin/lh-tpm2
TEST_BIN = tests/test_runner

all: $(TARGET)

$(TARGET): $(OBJS) $(MAIN_OBJ)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_BIN): $(OBJS) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -f src/*.o tests/*.o $(TARGET) $(TEST_BIN)
	rm -rf dist

dist: clean
	@mkdir -p dist
	tar --exclude-vcs --exclude='./dist' --exclude='./bin' --exclude='tests/test_runner' --exclude='*.o' --exclude='*.sealed' -czvf dist/lh-tpm2-provisioner-v0.1.0.tar.gz .

.PHONY: all test clean dist
