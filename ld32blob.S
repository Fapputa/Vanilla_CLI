/* i386 loader and libraries carried by the Linux executable (dbg.c, ld32_cache):
 * the files of $(ABYSS32) (~/abyss32 by default), included as they are at build
 * time. The Makefile assembles this file with -Wa,-I$(ABYSS32), where .incbin
 * looks for them; nothing here is read at run time. Linux only (never in the
 * Windows build). abyss_ld32_N .. abyss_ld32_N_end: the bytes of file N, in the
 * order of g_ld32_emb in dbg.c. */
#define F(sym, file)                                     \
    .globl sym; .hidden sym; .type sym, @object; .balign 16; \
    sym: .incbin file;                                   \
    .globl sym##_end; .hidden sym##_end; sym##_end:

    .section .rodata.abyss_ld32, "a", @progbits
F(abyss_ld32_0, "ld-linux.so.2")
F(abyss_ld32_1, "libc.so.6")
F(abyss_ld32_2, "libm.so.6")
F(abyss_ld32_3, "libdl.so.2")
F(abyss_ld32_4, "libpthread.so.0")
F(abyss_ld32_5, "librt.so.1")

    .section .note.GNU-stack, "", @progbits
