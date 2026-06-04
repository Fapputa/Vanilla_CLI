CC      = gcc
CFLAGS  = -O2 -march=native -Wall -Wextra -Wno-unused-parameter \
          -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lncurses -lpthread -lm

SRC     = gap_buf.c  \
          line_idx.c \
          undo.c     \
          syntax.c   \
          search.c   \
          colors.c   \
          pane.c     \
          run.c      \
          hex.c      \
          filetree.c \
          fileinfo.c \
          beautify.c \
          editor.c \
          highlight.c

OBJ     = $(SRC:.c=.o)
TARGET  = abyss

LSC_SRC     = lsc.c
LSC_BIN     = lsc
LSC_CFG_SRC = lsc-config.c
LSC_CFG_BIN = lsc-config

.PHONY: all clean debug lsc lsc-config

all: $(TARGET) lsc lsc-config

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c abyss.h
	$(CC) $(CFLAGS) -c -o $@ $<

lsc: $(LSC_SRC)
	$(CC) -O2 -Wall -Wextra -o $(LSC_BIN) $(LSC_SRC)

lsc-config: $(LSC_CFG_SRC)
	$(CC) -O2 -Wall -Wextra -o $(LSC_CFG_BIN) $(LSC_CFG_SRC) -lncurses

debug: CFLAGS += -g -DDEBUG -fsanitize=address -fno-omit-frame-pointer
debug: $(TARGET)

# Supprime uniquement les .o (les binaires restent pour que install.sh puisse les copier)
clean_obj:
	rm -f $(OBJ)

# Supprime tout (binaires inclus)
clean:
	rm -f $(OBJ) $(TARGET) $(LSC_BIN) $(LSC_CFG_BIN)