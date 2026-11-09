CC      = gcc
CFLAGS  = -O2 -march=native -Wall -Wextra -Wno-unused-parameter \
          -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
# ncursesw, the wide-character ncurses: alloc_pair (image.c) is only in it. Arch maps
# -lncurses onto it, Fedora does not (its libncurses is the narrow one, without it).
NCURSES_LIBS := $(shell pkg-config --libs ncursesw 2>/dev/null || echo -lncursesw)
LDFLAGS = $(NCURSES_LIBS) -lpthread -lm -lutil

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
SRC     += elfload.c peload.c disasm.c disview.c
CFLAGS  += -DHAVE_CAPSTONE
disasm.o: CFLAGS += $(shell pkg-config --cflags capstone)
LDFLAGS += $(shell pkg-config --libs capstone)
else
$(warning capstone introuvable via pkg-config : module d'analyse statique (F9 : elfload.c, disasm.c, disview.c) désactivé. Installez capstone puis relancez make.)
endif

OBJ     = $(SRC:.c=.o)
TARGET  = abyss

# Débogueur (F9) : chargeur i386 embarqué. Les fichiers de $(ABYSS32) sont
# inclus dans l'exécutable (ld32blob.S, .incbin) et extraits à l'exécution dans
# $XDG_CACHE_HOME/abyss/ seulement quand /lib/ld-linux.so.2 manque. Ce dossier
# ne sert qu'à la compilation ; absent, le module est retiré (avertissement).
.DEFAULT_GOAL := all
ABYSS32   ?= $(HOME)/abyss32
LD32_FILES = ld-linux.so.2 libc.so.6 libm.so.6 libdl.so.2 libpthread.so.0 librt.so.1
LD32 := $(shell [ "$$(uname -s)-$$(uname -m)" = Linux-x86_64 ] && cd "$(ABYSS32)" 2>/dev/null && ls $(LD32_FILES) >/dev/null 2>&1 && echo yes)
ifeq ($(LD32),yes)
OBJ     += ld32blob.o
dbg.o: EXTRA_DEFS = -DABYSS_LD32_BLOB
ld32blob.o: ld32blob.S $(addprefix $(ABYSS32)/,$(LD32_FILES))
	$(CC) -c -Wa,-I"$(ABYSS32)" -o $@ $<
else
$(warning $(ABYSS32) incomplet ($(LD32_FILES)) : chargeur i386 non embarqué, les programmes 32 bits ne se lancent dans le débogueur que si /lib/ld-linux.so.2 est installé.)
endif
# dbg.o est recompilé quand le chargeur apparaît ou disparaît (fichier réécrit,
# jamais supprimé)
LD32_STAMP = .ld32_stamp
$(shell [ "$$(cat $(LD32_STAMP) 2>/dev/null)" = "$(LD32)" ] || echo "$(LD32)" > $(LD32_STAMP))
dbg.o: $(LD32_STAMP)

LSC_SRC     = lsc.c
LSC_BIN     = lsc
LSC_CFG_SRC = lsc-config.c
LSC_CFG_BIN = lsc-config

.PHONY: all clean clean_obj debug lsc lsc-config

all: $(TARGET) lsc lsc-config

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c abyss.h imgdecode.h memscan.h elfload.h peload.h disasm.h disview.h
	$(CC) $(CFLAGS) $(EXTRA_DEFS) -c -o $@ $<

# debugger (F9): dbg.h is not in the list above
dbg.o disview.o editor.o memscan.o: dbg.h
dbg.o: dbg_bp.h

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
	rm -f $(OBJ) elfload.o peload.o disasm.o disview.o ld32blob.o $(TARGET) $(LSC_BIN) $(LSC_CFG_BIN) .capstone_yes .capstone_no