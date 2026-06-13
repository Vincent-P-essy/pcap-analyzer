# pcap-analyzer Makefile

CC      := gcc
CFLAGS  := -Wall -Wextra -std=c11 -O2
LDFLAGS := -lpcap

SRCDIR  := src
OBJDIR  := obj
TESTDIR := tests

SRCS    := $(wildcard $(SRCDIR)/*.c)
OBJS    := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

# Exclude main.o for test builds
LIB_SRCS := $(filter-out $(SRCDIR)/main.c,$(SRCS))
LIB_OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(LIB_SRCS))

TARGET  := pcap-analyzer
TEST_TARGET := $(OBJDIR)/test_detector

.PHONY: all test clean

all: $(OBJDIR) $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(OBJDIR) $(LIB_OBJS) $(OBJDIR)/test_detector.o
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(LIB_OBJS) $(OBJDIR)/test_detector.o $(LDFLAGS)
	$(TEST_TARGET)

$(OBJDIR)/test_detector.o: $(TESTDIR)/test_detector.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -c -o $@ $<

clean:
	rm -rf $(OBJDIR) $(TARGET)
