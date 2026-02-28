CC      = gcc
CFLAGS  = -O2 -march=native -Wall -Wextra -Wno-unused-parameter \
          -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lncurses -lpthread

SRC     = gap_buf.c  \
          line_idx.c \
          undo.c     \
          syntax.c   \
          search.c   \
          colors.c   \
          pane.c     \
          run.c      \
          editor.c

OBJ     = $(SRC:.c=.o)
TARGET  = abyss

.PHONY: all clean install debug

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c abyss.h
	$(CC) $(CFLAGS) -c -o $@ $<

debug: CFLAGS += -g -DDEBUG -fsanitize=address -fno-omit-frame-pointer
debug: $(TARGET)

clean:
	rm -f $(OBJ) $(TARGET) ./temp_bin

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/abyss