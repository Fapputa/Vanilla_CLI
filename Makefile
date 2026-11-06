CC      = gcc
CFLAGS  = -O2 -march=native -Wall -Wextra -Wno-unused-parameter \
          -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lncurses -lpthread -lm -lutil

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
          highlight.c \
          table.c    \
          image.c    \
          imgdecode.c \
          doc.c      \
          memscan.c  \
          memview.c  \
          dbg.c

# Analyse statique ELF (F9) : nécessite capstone (pkg-config), sinon le
# module est simplement retiré du build.
CAPSTONE := $(shell pkg-config --exists capstone 2>/dev/null && echo yes)
ifeq ($(CAPSTONE),yes)
SRC     += elfload.c disasm.c disview.c
CFLAGS  += -DHAVE_CAPSTONE
disasm.o: CFLAGS += $(shell pkg-config --cflags capstone)
LDFLAGS += $(shell pkg-config --libs capstone)
else
$(warning capstone introuvable via pkg-config : module d'analyse statique (F9 : elfload.c, disasm.c, disview.c) désactivé. Installez capstone puis relancez make.)
endif

OBJ     = $(SRC:.c=.o)
TARGET  = abyss

LSC_SRC     = lsc.c
LSC_BIN     = lsc
LSC_CFG_SRC = lsc-config.c
LSC_CFG_BIN = lsc-config

.PHONY: all clean clean_obj debug lsc lsc-config

all: $(TARGET) lsc lsc-config

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c abyss.h imgdecode.h memscan.h elfload.h disasm.h disview.h
	$(CC) $(CFLAGS) -c -o $@ $<

# debugger (F9): dbg.h is not in the list above
dbg.o disview.o editor.o: dbg.h

# editor.o / pane.o depend on HAVE_CAPSTONE: rebuilt when capstone
# appears or disappears
CAP_STAMP = .capstone_$(if $(filter yes,$(CAPSTONE)),yes,no)
$(CAP_STAMP):
	rm -f .capstone_yes .capstone_no
	touch $@
editor.o pane.o: $(CAP_STAMP)

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
	rm -f $(OBJ) elfload.o disasm.o disview.o $(TARGET) $(LSC_BIN) $(LSC_CFG_BIN) .capstone_yes .capstone_no