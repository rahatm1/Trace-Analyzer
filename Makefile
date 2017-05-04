#makefile for project 2 works both in linux and unix system now
CFLAGS = -Wall -Wextra -pedantic -std=gnu11 -g
LDFLAGS = -lpcap -lm
CC = gcc

all: trace_analyzer

trace_analyzer: util.o trace_analyzer.o
	$(CC) $(CFLAGS) -o trace_analyzer trace_analyzer.o util.o $(LDFLAGS)

util.o: util.c
	$(CC) $(CFLAGS) -c util.c

clean:
	-rm -rf *.o trace_analyzer.dSYM trace_analyzer
