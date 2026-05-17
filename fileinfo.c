#include "abyss.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <elf.h>

/* ── Minimal SHA-256 (public domain, no external deps) ─────────────── */
typedef struct { uint32_t state[8]; uint64_t count; uint8_t buf[64]; } SHA256_CTX2;
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define S1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define s0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define s1(x) (RR(x,17)^RR(x,19)^((x)>>10))
static void sha256_transform(SHA256_CTX2 *c, const uint8_t *d) {
    uint32_t a,b,e,f,g,h,t1,t2,w[64]; int i;
    uint32_t *s=c->state;
    for(i=0;i<16;i++) w[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for(i=16;i<64;i++) w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
    a=s[0];b=s[1];uint32_t c2=s[2];uint32_t d2=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for(i=0;i<64;i++){t1=h+S1(e)+CH(e,f,g)+K256[i]+w[i];t2=S0(a)+MAJ(a,b,c2);h=g;g=f;f=e;e=d2+t1;d2=c2;c2=b;b=a;a=t1+t2;}
    s[0]+=a;s[1]+=b;s[2]+=c2;s[3]+=d2;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
static void sha256_init(SHA256_CTX2 *c) {
    c->count=0;
    c->state[0]=0x6a09e667;c->state[1]=0xbb67ae85;c->state[2]=0x3c6ef372;c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f;c->state[5]=0x9b05688c;c->state[6]=0x1f83d9ab;c->state[7]=0x5be0cd19;
}
static void sha256_update(SHA256_CTX2 *c, const uint8_t *d, size_t len) {
    size_t i; unsigned idx=(unsigned)(c->count/8)%64;
    c->count+=len*8;
    for(i=0;i<len;i++){c->buf[idx++]=d[i];if(idx==64){sha256_transform(c,c->buf);idx=0;}}
}
static void sha256_final(SHA256_CTX2 *c, uint8_t *h) {
    unsigned idx=(unsigned)(c->count/8)%64; int i;
    c->buf[idx++]=0x80;
    if(idx>56){while(idx<64)c->buf[idx++]=0;sha256_transform(c,c->buf);idx=0;}
    while(idx<56)c->buf[idx++]=0;
    for(i=0;i<8;i++)c->buf[56+i]=(uint8_t)(c->count>>(56-8*i));
    sha256_transform(c,c->buf);
    for(i=0;i<8;i++){h[i*4]=(c->state[i]>>24)&0xff;h[i*4+1]=(c->state[i]>>16)&0xff;h[i*4+2]=(c->state[i]>>8)&0xff;h[i*4+3]=c->state[i]&0xff;}
}

/* ── Color pairs (allocated after filetree's range) ─────────────── */
#define FI_CP_BASE       110
#define FI_CP_HEADER     (FI_CP_BASE + 0)   /* bandeau titre */
#define FI_CP_SECTION    (FI_CP_BASE + 1)   /* section label */
#define FI_CP_KEY        (FI_CP_BASE + 2)   /* clé */
#define FI_CP_VAL        (FI_CP_BASE + 3)   /* valeur normale */
#define FI_CP_VAL_GOOD   (FI_CP_BASE + 4)   /* valeur positive (ex: writable) */
#define FI_CP_VAL_WARN   (FI_CP_BASE + 5)   /* valeur avertissement */
#define FI_CP_VAL_BAD    (FI_CP_BASE + 6)   /* valeur danger */
#define FI_CP_MAGIC      (FI_CP_BASE + 7)   /* magic number */
#define FI_CP_PERM_ON    (FI_CP_BASE + 8)   /* permission activée */
#define FI_CP_PERM_OFF   (FI_CP_BASE + 9)   /* permission absente */
#define FI_CP_BORDER     (FI_CP_BASE + 10)  /* bordure */
#define FI_CP_ENCODING   (FI_CP_BASE + 11)  /* encodage */
#define FI_CP_SIZE       (FI_CP_BASE + 12)  /* taille fichier */
#define FI_CP_DATE       (FI_CP_BASE + 13)  /* dates */

void fi_colors_init(void) {
    init_pair(FI_CP_HEADER,   COLOR_BLACK,   COLOR_CYAN);
    init_pair(FI_CP_SECTION,  COLOR_CYAN,    -1);
    init_pair(FI_CP_KEY,      COLOR_WHITE,   -1);
    init_pair(FI_CP_VAL,      COLOR_YELLOW,  -1);
    init_pair(FI_CP_VAL_GOOD, COLOR_GREEN,   -1);
    init_pair(FI_CP_VAL_WARN, COLOR_YELLOW,  -1);
    init_pair(FI_CP_VAL_BAD,  COLOR_RED,     -1);
    init_pair(FI_CP_MAGIC,    COLOR_MAGENTA, -1);
    init_pair(FI_CP_PERM_ON,  COLOR_GREEN,   -1);
    init_pair(FI_CP_PERM_OFF, COLOR_WHITE,   -1);
    init_pair(FI_CP_BORDER,   COLOR_CYAN,    -1);
    init_pair(FI_CP_ENCODING, COLOR_CYAN,    -1);
    init_pair(FI_CP_SIZE,     COLOR_MAGENTA, -1);
    init_pair(FI_CP_DATE,     COLOR_BLUE,    -1);
}

FileInfo *fi_new(void) {
    FileInfo *fi = calloc(1, sizeof *fi);
    fi->visible = false;
    fi->width   = FILEINFO_DEFAULT_W;
    return fi;
}

void fi_free(FileInfo *fi) {
    if (!fi) return;
    if (fi->win) delwin(fi->win);
    free(fi);
}

/* ── Magic number detection ─────────────────────────────────────── */

typedef struct {
    const char *ext;           /* extension attendue */
    const char *real_name;     /* nom complet du format */
    const char *description;   /* description fonctionnelle */
    const char *category;      /* catégorie */
    unsigned char magic[16];
    int    magic_len;
    int    magic_offset;       /* offset dans le fichier */
} MagicEntry;

static const MagicEntry MAGIC_DB[] = {
    /* Images */
    {".png",  "PNG Image",         "Image raster compressée sans perte (Portable Network Graphics). Supporte la transparence alpha.",
     "Image",  {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A}, 8, 0},
    {".jpg",  "JPEG Image",        "Image raster compressée avec perte (Joint Photographic Experts Group). Standard photographique.",
     "Image",  {0xFF,0xD8,0xFF}, 3, 0},
    {".gif",  "GIF Image",         "Image animée ou statique (Graphics Interchange Format). Palette 256 couleurs max.",
     "Image",  {0x47,0x49,0x46,0x38}, 4, 0},
    {".bmp",  "BMP Bitmap",        "Image bitmap Windows non compressée. Format natif Windows.",
     "Image",  {0x42,0x4D}, 2, 0},
    {".webp", "WebP Image",        "Format d'image moderne de Google, compression supérieure à JPEG/PNG.",
     "Image",  {0x57,0x45,0x42,0x50}, 4, 8},
    {".ico",  "ICO Icon",          "Fichier icône Windows, peut contenir plusieurs résolutions.",
     "Image",  {0x00,0x00,0x01,0x00}, 4, 0},
    {".tiff", "TIFF Image",        "Format d'image haute qualité (Tagged Image File Format). Utilisé en photographie pro.",
     "Image",  {0x49,0x49,0x2A,0x00}, 4, 0},

    /* Audio */
    {".mp3",  "MP3 Audio",         "Audio compressé avec perte (MPEG-1 Audio Layer III). Standard mondial de la musique numérique.",
     "Audio",  {0x49,0x44,0x33}, 3, 0},
    {".flac", "FLAC Audio",        "Audio compressé sans perte (Free Lossless Audio Codec). Qualité CD parfaite.",
     "Audio",  {0x66,0x4C,0x61,0x43}, 4, 0},
    {".wav",  "WAV Audio",         "Audio PCM non compressé (Waveform Audio). Qualité maximale, taille maximale.",
     "Audio",  {0x52,0x49,0x46,0x46}, 4, 0},
    {".ogg",  "OGG Vorbis",        "Audio compressé open-source (Ogg Vorbis). Alternative libre au MP3.",
     "Audio",  {0x4F,0x67,0x67,0x53}, 4, 0},
    {".aac",  "AAC Audio",         "Audio compressé avancé (Advanced Audio Coding). Successeur du MP3.",
     "Audio",  {0xFF,0xF1}, 2, 0},

    /* Vidéo */
    {".mp4",  "MP4 Video",         "Conteneur vidéo MPEG-4. Format standard pour la vidéo numérique moderne.",
     "Video",  {0x66,0x74,0x79,0x70}, 4, 4},
    {".mkv",  "Matroska Video",    "Conteneur vidéo open-source (Matroska). Supporte tous les codecs.",
     "Video",  {0x1A,0x45,0xDF,0xA3}, 4, 0},
    {".avi",  "AVI Video",         "Audio Video Interleave Microsoft. Format vidéo Windows classique.",
     "Video",  {0x52,0x49,0x46,0x46}, 4, 0},

    /* Documents */
    {".pdf",  "PDF Document",      "Document portable (Portable Document Format). Standard d'échange de documents Adobe.",
     "Document", {0x25,0x50,0x44,0x46,0x2D}, 5, 0},
    {".docx", "DOCX Document",     "Document Word XML compressé (Office Open XML). Format Microsoft Word moderne.",
     "Document", {0x50,0x4B,0x03,0x04}, 4, 0},
    {".xlsx", "Excel Spreadsheet", "Feuille de calcul XML compressée (Office Open XML). Format Microsoft Excel moderne.",
     "Document", {0x50,0x4B,0x03,0x04}, 4, 0},
    {".odt",  "ODF Text",          "Document texte Open Document Format. Standard ISO pour les suites bureautiques libres.",
     "Document", {0x50,0x4B,0x03,0x04}, 4, 0},

    /* Archives */
    {".zip",  "ZIP Archive",       "Archive compressée (ZIP). Format universel de compression de fichiers.",
     "Archive", {0x50,0x4B,0x03,0x04}, 4, 0},
    {".gz",   "GZIP Archive",      "Fichier compressé GZIP. Compression Unix standard.",
     "Archive", {0x1F,0x8B}, 2, 0},
    {".bz2",  "BZIP2 Archive",     "Archive compressée BZIP2. Meilleure compression que GZIP.",
     "Archive", {0x42,0x5A,0x68}, 3, 0},
    {".xz",   "XZ Archive",        "Archive compressée XZ/LZMA. Très haute compression.",
     "Archive", {0xFD,0x37,0x7A,0x58,0x5A,0x00}, 6, 0},
    {".7z",   "7-Zip Archive",     "Archive 7-Zip haute compression. Format très efficace.",
     "Archive", {0x37,0x7A,0xBC,0xAF,0x27,0x1C}, 6, 0},
    {".tar",  "TAR Archive",       "Archive tar (Tape ARchive). Regroupement de fichiers sans compression.",
     "Archive", {0x75,0x73,0x74,0x61,0x72}, 5, 257},
    {".rar",  "RAR Archive",       "Archive RAR compressée (Roshal ARchive). Haute compression propriétaire.",
     "Archive", {0x52,0x61,0x72,0x21,0x1A,0x07}, 6, 0},
    {".iso",  "ISO Image",         "Image de disque optique (ISO 9660). Copie exacte d'un CD/DVD.",
     "Archive", {0x43,0x44,0x30,0x30,0x31}, 5, 32769},
    {".deb",  "Debian Package",    "Paquet logiciel Debian/Ubuntu. Contient binaires, métadonnées et scripts d'installation.",
     "Package", {0x21,0x3C,0x61,0x72,0x63,0x68,0x3E}, 7, 0},
    {".rpm",  "RPM Package",       "Paquet logiciel RPM (Red Hat Package Manager). Format Fedora/RHEL/CentOS.",
     "Package", {0xED,0xAB,0xEE,0xDB}, 4, 0},

    /* Exécutables & bibliothèques */
    {".elf",  "ELF Executable",    "Executable and Linkable Format Linux/Unix. Binaire natif Linux.",
     "Binary", {0x7F,0x45,0x4C,0x46}, 4, 0},
    {".so",   "Shared Library",    "Bibliothèque partagée ELF Linux. Chargée dynamiquement à l'exécution.",
     "Binary", {0x7F,0x45,0x4C,0x46}, 4, 0},
    {".exe",  "PE Executable",     "Portable Executable Windows (PE). Binaire natif Windows.",
     "Binary", {0x4D,0x5A}, 2, 0},
    {".dll",  "DLL Library",       "Dynamic Link Library Windows. Bibliothèque partagée Windows.",
     "Binary", {0x4D,0x5A}, 2, 0},
    {".wasm", "WebAssembly",       "Module WebAssembly. Bytecode portable haute performance pour le web.",
     "Binary", {0x00,0x61,0x73,0x6D}, 4, 0},

    /* Données & bases */
    {".sqlite","SQLite Database",  "Base de données SQLite. SGBD embarqué le plus répandu au monde.",
     "Database", {0x53,0x51,0x4C,0x69,0x74,0x65,0x20,0x66,0x6F,0x72,0x6D,0x61,0x74,0x20,0x33,0x00}, 16, 0},
    {".dmp",  "Core Dump / Dump",  "Dump mémoire ou crash dump. Instantané de la mémoire d'un processus.",
     "Debug", {0}, 0, 0},

    /* Polices */
    {".ttf",  "TrueType Font",     "Police de caractères TrueType (Apple/Microsoft). Format vectoriel scalable.",
     "Font",   {0x00,0x01,0x00,0x00,0x00}, 5, 0},
    {".otf",  "OpenType Font",     "Police OpenType (Adobe/Microsoft). Supérieure au TrueType, supporte plus de glyphes.",
     "Font",   {0x4F,0x54,0x54,0x4F}, 4, 0},
    {".woff", "WOFF Font",         "Web Open Font Format. Police optimisée pour le web.",
     "Font",   {0x77,0x4F,0x46,0x46}, 4, 0},

    /* Données scientifiques & médias spéciaux */
    {".mid",  "MIDI File",         "Fichier MIDI (Musical Instrument Digital Interface). Séquenceur musical numérique.",
     "Audio",  {0x4D,0x54,0x68,0x64}, 4, 0},
    {".psd",  "Photoshop Document","Fichier Photoshop natif (Adobe). Supporte les calques et effets.",
     "Image",  {0x38,0x42,0x50,0x53}, 4, 0},
    {".blend","Blender File",      "Scène 3D Blender. Contient maillages, matériaux, animations.",
     "3D",     {0x42,0x4C,0x45,0x4E,0x44,0x45,0x52}, 7, 0},
    {".pcap", "Packet Capture",    "Capture réseau PCAP (Wireshark/tcpdump). Enregistrement de trafic réseau.",
     "Network",{0xD4,0xC3,0xB2,0xA1}, 4, 0},
    {".vmdk", "VMware Disk",       "Image disque VMware (Virtual Machine Disk). Disque dur virtuel VMware.",
     "Virtual",{0x4B,0x44,0x4D}, 3, 0},
    {".qcow2","QCOW2 Disk Image",  "Image disque QEMU/KVM (QEMU Copy-On-Write). Disque dur virtuel Linux.",
     "Virtual",{0x51,0x46,0x49,0xFB}, 4, 0},
    {".heic", "HEIC Image",        "Image haute efficacité (High Efficiency Image Container). Format iPhone/Apple.",
     "Image",  {0x66,0x74,0x79,0x70}, 4, 4},
    {".avif", "AVIF Image",        "Image AV1 (AV1 Image File Format). Compression supérieure au WebP.",
     "Image",  {0x66,0x74,0x79,0x70}, 4, 4},
    {".pem",  "PEM Certificate",   "Certificat ou clé PEM (Privacy Enhanced Mail). Format standard TLS/SSL.",
     "Security",{0x2D,0x2D,0x2D,0x2D,0x2D}, 5, 0},
    {".key",  "Private Key",       "Clé privée cryptographique. À protéger impérativement.",
     "Security",{0}, 0, 0},
    {".p12",  "PKCS#12 Certificate","Certificat + clé privée PKCS#12. Utilisé pour l'import/export de certificats TLS.",
     "Security",{0x30,0x82}, 2, 0},
    {".class","Java Bytecode",     "Classe Java compilée. Exécutée par la JVM (Java Virtual Machine).",
     "Bytecode",{0xCA,0xFE,0xBA,0xBE}, 4, 0},
    {".pyc",  "Python Bytecode",   "Module Python précompilé. Généré automatiquement par l'interpréteur.",
     "Bytecode",{0}, 0, 0},
    {NULL, NULL, NULL, NULL, {0}, 0, 0}
};

/* Detect magic from raw bytes */
static const MagicEntry *detect_magic(const char *path) {
    unsigned char buf[512];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    if (n <= 0) return NULL;

    for (int i = 0; MAGIC_DB[i].ext != NULL; i++) {
        const MagicEntry *m = &MAGIC_DB[i];
        if (m->magic_len <= 0) continue;
        int off = m->magic_offset;
        if (off + m->magic_len > (int)n) continue;
        if (memcmp(buf + off, m->magic, m->magic_len) == 0)
            return m;
    }
    return NULL;
}

/* Find ext entry by extension */
static const MagicEntry *find_by_ext(const char *ext) {
    if (!ext) return NULL;
    for (int i = 0; MAGIC_DB[i].ext != NULL; i++)
        if (strcasecmp(MAGIC_DB[i].ext, ext) == 0)
            return &MAGIC_DB[i];
    return NULL;
}

/* ── Encoding detection ─────────────────────────────────────────── */
static const char *detect_encoding(const char *path) {
    unsigned char buf[4096];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return "Unknown";
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    if (n <= 0) return "Empty";

    /* BOM checks */
    if (n >= 3 && buf[0]==0xEF && buf[1]==0xBB && buf[2]==0xBF) return "UTF-8 BOM";
    if (n >= 2 && buf[0]==0xFF && buf[1]==0xFE) return "UTF-16 LE";
    if (n >= 2 && buf[0]==0xFE && buf[1]==0xFF) return "UTF-16 BE";
    if (n >= 4 && buf[0]==0x00 && buf[1]==0x00 && buf[2]==0xFE && buf[3]==0xFF) return "UTF-32 BE";
    if (n >= 4 && buf[0]==0xFF && buf[1]==0xFE && buf[2]==0x00 && buf[3]==0x00) return "UTF-32 LE";

    /* Check binary */
    int nulls = 0, highs = 0;
    bool valid_utf8 = true;
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == 0x00) nulls++;
        if (buf[i] > 0x7F)  highs++;
    }
    if (nulls > n / 20) return "Binary";

    /* Try valid UTF-8 */
    for (ssize_t i = 0; i < n && valid_utf8; ) {
        unsigned char c = buf[i];
        int bytes = 0;
        if      (c < 0x80)                    bytes = 1;
        else if ((c & 0xE0) == 0xC0)          bytes = 2;
        else if ((c & 0xF0) == 0xE0)          bytes = 3;
        else if ((c & 0xF8) == 0xF0)          bytes = 4;
        else { valid_utf8 = false; break; }
        if (i + bytes > n) { valid_utf8 = false; break; }
        for (int j = 1; j < bytes; j++)
            if ((buf[i+j] & 0xC0) != 0x80) { valid_utf8 = false; break; }
        i += bytes;
    }
    if (valid_utf8 && highs > 0) return "UTF-8";
    if (valid_utf8 && highs == 0) return "ASCII";
    return "Latin-1 / ISO-8859";
}

/* ── Line ending detection ──────────────────────────────────────── */
static const char *detect_line_endings(const char *path) {
    unsigned char buf[8192];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return "Unknown";
    ssize_t n = read(fd, buf, sizeof buf);
    close(fd);
    int crlf = 0, lf = 0, cr = 0;
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\r') {
            if (i+1 < n && buf[i+1] == '\n') { crlf++; i++; }
            else cr++;
        } else if (buf[i] == '\n') lf++;
    }
    if (crlf > 0 && lf == 0 && cr == 0) return "CRLF (Windows)";
    if (lf > 0 && crlf == 0 && cr == 0) return "LF (Unix/Linux)";
    if (cr > 0 && crlf == 0 && lf == 0) return "CR (Classic Mac)";
    if (crlf > 0 || lf > 0 || cr > 0)   return "Mixed";
    return "None";
}

/* ── Human-readable size ────────────────────────────────────────── */
static void fmt_size(off_t sz, char *out, size_t outlen) {
    if      (sz < 1024LL)              snprintf(out, outlen, "%lld B", (long long)sz);
    else if (sz < 1024LL*1024)         snprintf(out, outlen, "%.2f KiB (%lld bytes)", (double)sz/1024.0, (long long)sz);
    else if (sz < 1024LL*1024*1024)    snprintf(out, outlen, "%.2f MiB (%lld bytes)", (double)sz/(1024.0*1024), (long long)sz);
    else if (sz < 1024LL*1024*1024*1024) snprintf(out, outlen, "%.2f GiB (%lld bytes)", (double)sz/(1024.0*1024*1024), (long long)sz);
    else                               snprintf(out, outlen, "%.2f TiB (%lld bytes)", (double)sz/(1024.0*1024*1024*1024), (long long)sz);
}

/* ── Permission string ──────────────────────────────────────────── */
static void fmt_perms(mode_t mode, char *out) {
    out[0]  = S_ISDIR(mode)  ? 'd' : S_ISLNK(mode) ? 'l' : '-';
    out[1]  = (mode & S_IRUSR) ? 'r' : '-';
    out[2]  = (mode & S_IWUSR) ? 'w' : '-';
    out[3]  = (mode & S_IXUSR) ? 'x' : '-';
    out[4]  = (mode & S_IRGRP) ? 'r' : '-';
    out[5]  = (mode & S_IWGRP) ? 'w' : '-';
    out[6]  = (mode & S_IXGRP) ? 'x' : '-';
    out[7]  = (mode & S_IROTH) ? 'r' : '-';
    out[8]  = (mode & S_IWOTH) ? 'w' : '-';
    out[9]  = (mode & S_IXOTH) ? 'x' : '-';
    out[10] = '\0';
}

/* ── File type string ───────────────────────────────────────────── */
static const char *file_type_str(mode_t mode) {
    if (S_ISREG(mode))  return "Regular file";
    if (S_ISDIR(mode))  return "Directory";
    if (S_ISLNK(mode))  return "Symbolic link";
    if (S_ISCHR(mode))  return "Character device";
    if (S_ISBLK(mode))  return "Block device";
    if (S_ISFIFO(mode)) return "FIFO / Named pipe";
    if (S_ISSOCK(mode)) return "Socket";
    return "Unknown";
}

/* ── Wrap text to fit width ─────────────────────────────────────── */
static void draw_wrapped(WINDOW *win, int *vrowp, int scroll, int win_h,
                         int col, int width, int cp, const char *text) {
    if (!text || !text[0]) return;
    char line[256];
    int w = width - col;
    if (w <= 0) return;
    size_t len = strlen(text);
    size_t pos = 0;
    while (pos < len) {
        int screen_row = 1 + *vrowp - scroll;
        if (screen_row >= win_h) break;
        size_t take = (size_t)w < len - pos ? (size_t)w : len - pos;
        if (pos + take < len) {
            size_t last_sp = take;
            for (size_t i = take; i > 0; i--)
                if (text[pos+i-1] == ' ') { last_sp = i; break; }
            take = last_sp;
        }
        if (*vrowp >= scroll && screen_row >= 1) {
            memcpy(line, text + pos, take);
            line[take] = '\0';
            if (cp) wattron(win, COLOR_PAIR(cp));
            mvwprintw(win, screen_row, col, "%s", line);
            if (cp) wattroff(win, COLOR_PAIR(cp));
        }
        pos += take;
        while (pos < len && text[pos] == ' ') pos++;
        (*vrowp)++;
    }
}

/* ─── Main render ─────────────────────────────────────────────── */
void fi_analyze(FileInfo *fi, const char *path) {
    if (!path || !path[0]) {
        fi->has_data = false;
        return;
    }
    strncpy(fi->path, path, sizeof(fi->path)-1);
    fi->has_data = true;
}

void fi_render(FileInfo *fi, WINDOW *win, int win_h, int win_w) {
    if (!win || win_h < 4 || win_w < 8) return;
    werase(win);

    /* Bordure gauche */
    wattron(win, COLOR_PAIR(FI_CP_BORDER) | A_BOLD);
    for (int y = 0; y < win_h; y++) mvwaddch(win, y, 0, ACS_VLINE);
    wattroff(win, COLOR_PAIR(FI_CP_BORDER) | A_BOLD);

    int w = win_w - 1;   /* largeur utile (après la bordure) */
    int x = 1;           /* début de contenu */

    if (!fi->has_data || !fi->path[0]) {
        wattron(win, COLOR_PAIR(FI_CP_KEY));
        mvwprintw(win, 2, x, " No file open");
        wattroff(win, COLOR_PAIR(FI_CP_KEY));
        wnoutrefresh(win);
        return;
    }

    const char *path = fi->path;

    /* ── stat ── */
    struct stat st;
    bool has_stat = (lstat(path, &st) == 0);

    /* ── magic + ext info ── */
    const char *dot = strrchr(path, '.');
    const char *ext = dot ? dot : "";
    const char *basename = strrchr(path, '/');
    basename = basename ? basename+1 : path;

    const MagicEntry *by_magic = has_stat && S_ISREG(st.st_mode)
                                 ? detect_magic(path) : NULL;
    const MagicEntry *by_ext   = find_by_ext(ext);
    const MagicEntry *info     = by_magic ? by_magic : by_ext;

    int scroll = fi->scroll_row;

    /* ══ Header (toujours visible, pas scrollable) ═══════════════ */
    {
        wattron(win, COLOR_PAIR(FI_CP_HEADER) | A_BOLD);
        char hdr[128];
        snprintf(hdr, sizeof hdr, " File Inspector ");
        mvwprintw(win, 0, 0, "%-*s", win_w, hdr);
        wattroff(win, COLOR_PAIR(FI_CP_HEADER) | A_BOLD);
    }

    /* Scroll : vrow = indice de ligne logique (0-based).
       row   = ligne écran = 1 + vrow - scroll.
       ROW_VIS : la ligne est visible si row est dans [1, win_h[.
       ADVANCE() : passe à la ligne logique suivante — TOUJOURS appelé,
                   même si ROW_VIS était faux. */
    int vrow = 0;
    #undef  ROW_VIS
    #define ROW_VIS   (vrow >= scroll && (1 + vrow - scroll) < win_h)
    #define row       (1 + vrow - scroll)
    #define ADVANCE() do { vrow++; } while(0)


    /* ══ Section: Identité ════════════════════════════════════════ */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
        mvwprintw(win, row, x, "━━ Identity ");
        wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
    } ADVANCE();

    /* Nom */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_KEY));
        mvwprintw(win, row, x, "Name  : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
        wattron(win, COLOR_PAIR(FI_CP_VAL) | A_BOLD);
        mvwprintw(win, row, x+8, "%-*.*s", w-9, w-9, basename);
        wattroff(win, COLOR_PAIR(FI_CP_VAL) | A_BOLD);
    } ADVANCE();

    /* Extension (from filename) */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_KEY));
        mvwprintw(win, row, x, "Ext   : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
        wattron(win, COLOR_PAIR(FI_CP_VAL));
        mvwprintw(win, row, x+8, "%s", ext[0] ? ext : "(none)");
        wattroff(win, COLOR_PAIR(FI_CP_VAL));
    } ADVANCE();

    /* Real extension (from magic number) */
    if (has_stat && S_ISREG(st.st_mode)) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "RealExt:"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            bool ext_match = by_magic && by_ext && strcmp(by_magic->ext, by_ext->ext)==0;
            bool ext_mismatch = by_magic && by_ext && strcmp(by_magic->ext, by_ext->ext)!=0;
            if (by_magic) {
                int cp_re = ext_mismatch ? FI_CP_VAL_BAD : FI_CP_VAL_GOOD;
                wattron(win, COLOR_PAIR(cp_re) | A_BOLD);
                mvwprintw(win, row, x+9, "%s", by_magic->ext);
                wattroff(win, COLOR_PAIR(cp_re) | A_BOLD);
                if (ext_mismatch) {
                    wattron(win, COLOR_PAIR(FI_CP_VAL_BAD));
                    mvwprintw(win, row, x+9+(int)strlen(by_magic->ext)+1, "⚠RENAMED");
                    wattroff(win, COLOR_PAIR(FI_CP_VAL_BAD));
                }
            } else {
                wattron(win, COLOR_PAIR(FI_CP_VAL_WARN));
                mvwprintw(win, row, x+9, "(unknown)");
                wattroff(win, COLOR_PAIR(FI_CP_VAL_WARN));
            }
            (void)(by_magic && by_ext && strcmp(by_magic->ext, by_ext->ext)==0); /* ext_match used above */
        } ADVANCE();
    }

    /* Format (human name from magic) */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_KEY));
        mvwprintw(win, row, x, "Format: "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
        if (by_magic) {
            wattron(win, COLOR_PAIR(FI_CP_VAL_GOOD) | A_BOLD);
            mvwprintw(win, row, x+8, "%-*.*s", w-9, w-9, by_magic->real_name);
            wattroff(win, COLOR_PAIR(FI_CP_VAL_GOOD) | A_BOLD);
        } else if (by_ext) {
            wattron(win, COLOR_PAIR(FI_CP_VAL_WARN));
            mvwprintw(win, row, x+8, "%-*.*s~ext", w-13, w-13, by_ext->real_name);
            wattroff(win, COLOR_PAIR(FI_CP_VAL_WARN));
        } else {
            wattron(win, COLOR_PAIR(FI_CP_VAL_BAD));
            mvwprintw(win, row, x+8, "Unknown");
            wattroff(win, COLOR_PAIR(FI_CP_VAL_BAD));
        }
    } ADVANCE();

    /* Catégorie */
    if (info) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Cat   : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_MAGIC));
            mvwprintw(win, row, x+8, "%s", info->category);
            wattroff(win, COLOR_PAIR(FI_CP_MAGIC));
        } ADVANCE();
    }

    /* Magic bytes */
    if (by_magic && by_magic->magic_len > 0) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Magic :"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_MAGIC) | A_BOLD);
            int c2 = x + 8;
            for (int mi = 0; mi < by_magic->magic_len && mi < 8; mi++) {
                if (c2 + 3 >= win_w) break;
                mvwprintw(win, row, c2, "%02X ", (unsigned char)by_magic->magic[mi]);
                c2 += 3;
            }
            if (by_magic->magic_offset > 0) {
                mvwprintw(win, row, c2, "@%d", by_magic->magic_offset);
            }
            wattroff(win, COLOR_PAIR(FI_CP_MAGIC) | A_BOLD);
        } ADVANCE();
    }

    /* Description (avec word-wrap) */
    if (info && info->description) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Desc  :"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
        } ADVANCE();
        draw_wrapped(win, &vrow, scroll, win_h, x+1, w, FI_CP_VAL, info->description);
    }

    /* ══ Section: Localisation ════════════════════════════════════ */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
        mvwprintw(win, row, x, "━━ Location ");
        wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
    } ADVANCE();

    /* Chemin complet */
    {
        char resolved[4096] = "";
        if (!realpath(path, resolved)) strncpy(resolved, path, sizeof(resolved)-1);
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Path  :"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
        } ADVANCE();
        draw_wrapped(win, &vrow, scroll, win_h, x+1, w, FI_CP_VAL, resolved[0] ? resolved : path);
    }

    /* Inode */
    if (has_stat) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Inode : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_VAL));
            mvwprintw(win, row, x+8, "%lu", (unsigned long)st.st_ino);
            wattroff(win, COLOR_PAIR(FI_CP_VAL));
        } ADVANCE();
    }

    /* Device */
    if (has_stat) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Device: "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_VAL));
            mvwprintw(win, row, x+8, "%lu (maj:%lu min:%lu)",
                      (unsigned long)st.st_dev,
                      (unsigned long)major(st.st_dev),
                      (unsigned long)minor(st.st_dev));
            wattroff(win, COLOR_PAIR(FI_CP_VAL));
        } ADVANCE();
    }

    /* Hard links */
    if (has_stat) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Links : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            int cp_lnk = st.st_nlink > 1 ? FI_CP_VAL_WARN : FI_CP_VAL;
            wattron(win, COLOR_PAIR(cp_lnk));
            mvwprintw(win, row, x+8, "%lu hard link%s",
                      (unsigned long)st.st_nlink, st.st_nlink>1?"s":"");
            wattroff(win, COLOR_PAIR(cp_lnk));
        } ADVANCE();
    }

    /* ══ Section: Taille ═════════════════════════════════════════ */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
        mvwprintw(win, row, x, "━━ Size ");
        wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
    } ADVANCE();

    if (has_stat) {
        char szbuf[128];
        fmt_size(st.st_size, szbuf, sizeof szbuf);
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Size  : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_SIZE) | A_BOLD);
            mvwprintw(win, row, x+8, "%-*.*s", w-9, w-9, szbuf);
            wattroff(win, COLOR_PAIR(FI_CP_SIZE) | A_BOLD);
        } ADVANCE();
    }

    if (has_stat) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Blocks: "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_VAL));
            {
                char blkbuf[128];
                snprintf(blkbuf, sizeof blkbuf, "%lld x 512B = %lld B",
                         (long long)st.st_blocks,
                         (long long)st.st_blocks * 512);
                mvwprintw(win, row, x+8, "%-*.*s", w-9, w-9, blkbuf);
            }
            wattroff(win, COLOR_PAIR(FI_CP_VAL));
        } ADVANCE();
    }

    /* ══ Section: Encodage ════════════════════════════════════════ */
    if (has_stat && S_ISREG(st.st_mode)) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
            mvwprintw(win, row, x, "━━ Encoding ");
            wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
        } ADVANCE();
        {
            const char *enc = detect_encoding(path);
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Encod : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                int cp_enc = (strcmp(enc,"Binary")==0) ? FI_CP_VAL_BAD :
                             (strcmp(enc,"Unknown")==0) ? FI_CP_VAL_WARN : FI_CP_ENCODING;
                wattron(win, COLOR_PAIR(cp_enc) | A_BOLD);
                mvwprintw(win, row, x+8, "%s", enc);
                wattroff(win, COLOR_PAIR(cp_enc) | A_BOLD);
            } ADVANCE();
        }
        {
            const char *le = detect_line_endings(path);
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Lines : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                int cp_le = (strcmp(le,"Mixed")==0) ? FI_CP_VAL_WARN : FI_CP_VAL;
                wattron(win, COLOR_PAIR(cp_le));
                mvwprintw(win, row, x+8, "%s", le);
                wattroff(win, COLOR_PAIR(cp_le));
            } ADVANCE();
        }
    }

    /* ══ Section: Permissions ════════════════════════════════════ */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
        mvwprintw(win, row, x, "━━ Permissions ");
        wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
    } ADVANCE();

    if (has_stat) {
        char perms[12];
        fmt_perms(st.st_mode, perms);
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Mode  : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));

            /* Afficher chaque caractère avec sa couleur */
            int px = x + 8;
            for (int pi = 0; pi < 10 && px < win_w-1; pi++, px++) {
                if (perms[pi] == '-') {
                    wattron(win, COLOR_PAIR(FI_CP_PERM_OFF) | A_DIM);
                    mvwaddch(win, row, px, '-');
                    wattroff(win, COLOR_PAIR(FI_CP_PERM_OFF) | A_DIM);
                } else {
                    wattron(win, COLOR_PAIR(FI_CP_PERM_ON) | A_BOLD);
                    mvwaddch(win, row, px, perms[pi]);
                    wattroff(win, COLOR_PAIR(FI_CP_PERM_ON) | A_BOLD);
                }
            }
            /* octal */
            wattron(win, COLOR_PAIR(FI_CP_VAL));
            mvwprintw(win, row, px+1, "(%04o)", (unsigned)(st.st_mode & 07777));
            wattroff(win, COLOR_PAIR(FI_CP_VAL));

            /* Bits spéciaux */
            if (st.st_mode & S_ISUID) {
                wattron(win, COLOR_PAIR(FI_CP_VAL_BAD) | A_BOLD);
                mvwprintw(win, row, px+8, "SUID");
                wattroff(win, COLOR_PAIR(FI_CP_VAL_BAD) | A_BOLD);
            }
            if (st.st_mode & S_ISGID) {
                wattron(win, COLOR_PAIR(FI_CP_VAL_WARN) | A_BOLD);
                mvwprintw(win, row, px+13, "SGID");
                wattroff(win, COLOR_PAIR(FI_CP_VAL_WARN) | A_BOLD);
            }
            if (st.st_mode & S_ISVTX) {
                wattron(win, COLOR_PAIR(FI_CP_VAL_GOOD) | A_BOLD);
                mvwprintw(win, row, px+18, "STICKY");
                wattroff(win, COLOR_PAIR(FI_CP_VAL_GOOD) | A_BOLD);
            }
        } ADVANCE();
    }

    /* Type de fichier */
    if (has_stat) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Type  : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_VAL));
            mvwprintw(win, row, x+8, "%s", file_type_str(st.st_mode));
            wattroff(win, COLOR_PAIR(FI_CP_VAL));
        } ADVANCE();
    }

    /* Propriétaire — wrap si trop long */
    if (has_stat) {
        struct passwd *pw = getpwuid(st.st_uid);
        struct group  *gr = getgrgid(st.st_gid);
        char user_buf[128], grp_buf[128];
        snprintf(user_buf, sizeof user_buf, "%s (%d)",
                 pw ? pw->pw_name : "?", (int)st.st_uid);
        snprintf(grp_buf,  sizeof grp_buf,  "%s (%d)",
                 gr ? gr->gr_name : "?", (int)st.st_gid);
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Owner : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_VAL_GOOD));
            mvwprintw(win, row, x+8, "%-.*s", w-8, user_buf);
            wattroff(win, COLOR_PAIR(FI_CP_VAL_GOOD));
        } ADVANCE();
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_KEY));
            mvwprintw(win, row, x, "Group : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            wattron(win, COLOR_PAIR(FI_CP_VAL_GOOD));
            mvwprintw(win, row, x+8, "%-.*s", w-8, grp_buf);
            wattroff(win, COLOR_PAIR(FI_CP_VAL_GOOD));
        } ADVANCE();
    }

    /* Accès R/W/X pour l'utilisateur courant */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_KEY));
        mvwprintw(win, row, x, "Access: "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
        int ax = x + 8;
        const char *labels[] = {"R", "W", "X"};
        int modes[] = {R_OK, W_OK, X_OK};
        for (int ai = 0; ai < 3 && ax + 3 < win_w; ai++) {
            bool ok = (access(path, modes[ai]) == 0);
            wattron(win, COLOR_PAIR(ok ? FI_CP_PERM_ON : FI_CP_PERM_OFF) | (ok ? A_BOLD : A_DIM));
            mvwprintw(win, row, ax, "%s", ok ? labels[ai] : "-");
            wattroff(win, COLOR_PAIR(ok ? FI_CP_PERM_ON : FI_CP_PERM_OFF) | (ok ? A_BOLD : A_DIM));
            ax += 2;
        }
    } ADVANCE();

    /* ══ Section: Dates ══════════════════════════════════════════ */
    if (ROW_VIS) {
        wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
        mvwprintw(win, row, x, "━━ Timestamps ");
        wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
    } ADVANCE();

    if (has_stat) {
        struct { const char *label; time_t t; } times[] = {
            {"Modify", st.st_mtime},
            {"Access", st.st_atime},
            {"Change", st.st_ctime},
        };
        for (int ti = 0; ti < 3; ti++) {
            if (ROW_VIS) {
                char tbuf[64];
                struct tm *tm_info = localtime(&times[ti].t);
                strftime(tbuf, sizeof tbuf, "%Y-%m-%d %H:%M:%S", tm_info);
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "%-6s: ", times[ti].label);
                wattroff(win, COLOR_PAIR(FI_CP_KEY));
                wattron(win, COLOR_PAIR(FI_CP_DATE));
                mvwprintw(win, row, x+8, "%s", tbuf);
                wattroff(win, COLOR_PAIR(FI_CP_DATE));
            } ADVANCE();
        }
    }

    /* ══ Section: SHA-256 ═══════════════════════════════════════ */
    if (has_stat && S_ISREG(st.st_mode) && st.st_size > 0
            && st.st_size < 512*1024*1024) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
            mvwprintw(win, row, x, "━━ Checksum ");
            wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
        } ADVANCE();
        {
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                SHA256_CTX2 sctx; sha256_init(&sctx);
                unsigned char cbuf[65536]; ssize_t nr;
                while ((nr = read(fd, cbuf, sizeof cbuf)) > 0)
                    sha256_update(&sctx, cbuf, (size_t)nr);
                close(fd);
                uint8_t digest[32]; sha256_final(&sctx, digest);
                char hexdigest[65];
                for (int di = 0; di < 32; di++)
                    snprintf(hexdigest + di*2, 3, "%02x", digest[di]);
                if (ROW_VIS) {
                    wattron(win, COLOR_PAIR(FI_CP_KEY));
                    mvwprintw(win, row, x, "SHA256:"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                } ADVANCE();
                wattron(win, COLOR_PAIR(FI_CP_MAGIC) | A_BOLD);
                if (ROW_VIS) { mvwprintw(win, row, x+1, "%.32s", hexdigest); } ADVANCE();
                if (ROW_VIS) { mvwprintw(win, row, x+1, "%.32s", hexdigest+32); } ADVANCE();
                wattroff(win, COLOR_PAIR(FI_CP_MAGIC) | A_BOLD);
            }
        }
    }

    /* ══ Section: Contenu texte ══════════════════════════════════ */
    if (has_stat && S_ISREG(st.st_mode) && st.st_size > 0) {
        const char *enc = detect_encoding(path);
        if (strcmp(enc,"Binary") != 0 && strcmp(enc,"Unknown") != 0) {
            /* Compter lignes / mots / chars */
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                long lines = 0, words = 0, chars = 0;
                bool in_word = false;
                unsigned char cbuf[65536];
                ssize_t nr;
                while ((nr = read(fd, cbuf, sizeof cbuf)) > 0) {
                    for (ssize_t ci = 0; ci < nr; ci++) {
                        chars++;
                        if (cbuf[ci] == '\n') lines++;
                        if (isspace(cbuf[ci])) in_word = false;
                        else if (!in_word) { in_word = true; words++; }
                    }
                }
                close(fd);

                if (ROW_VIS) {
                    wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
                    mvwprintw(win, row, x, "━━ Text Stats ");
                    wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
                } ADVANCE();
                if (ROW_VIS) {
                    wattron(win, COLOR_PAIR(FI_CP_KEY));
                    mvwprintw(win, row, x, "Lines : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                    wattron(win, COLOR_PAIR(FI_CP_VAL));
                    mvwprintw(win, row, x+8, "%ld", lines);
                    wattroff(win, COLOR_PAIR(FI_CP_VAL));
                } ADVANCE();
                if (ROW_VIS) {
                    wattron(win, COLOR_PAIR(FI_CP_KEY));
                    mvwprintw(win, row, x, "Words : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                    wattron(win, COLOR_PAIR(FI_CP_VAL));
                    mvwprintw(win, row, x+8, "%ld", words);
                    wattroff(win, COLOR_PAIR(FI_CP_VAL));
                } ADVANCE();
                if (ROW_VIS) {
                    wattron(win, COLOR_PAIR(FI_CP_KEY));
                    mvwprintw(win, row, x, "Chars : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                    wattron(win, COLOR_PAIR(FI_CP_VAL));
                    mvwprintw(win, row, x+8, "%ld", chars);
                    wattroff(win, COLOR_PAIR(FI_CP_VAL));
                } ADVANCE();
            }
        }
    }

    /* ══ Section: Lien symbolique ════════════════════════════════ */
    if (has_stat && S_ISLNK(st.st_mode)) {
        char lnk_target[4096] = "";
        ssize_t lr = readlink(path, lnk_target, sizeof(lnk_target)-1);
        if (lr > 0) {
            lnk_target[lr] = '\0';
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
                mvwprintw(win, row, x, "━━ Symlink ");
                wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
            } ADVANCE();
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Target:"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
            } ADVANCE();
            draw_wrapped(win, &vrow, scroll, win_h, x+1, w, FI_CP_VAL_WARN, lnk_target);
        }
    }


    /* ══ Section: Binary Info (ELF) ═════════════════════════════ */
    if (has_stat && S_ISREG(st.st_mode) && st.st_size >= 64) {
        /* Check ELF magic */
        unsigned char elfhdr[64];
        int efd = open(path, O_RDONLY);
        bool is_elf = false;
        if (efd >= 0) {
            if (read(efd, elfhdr, 64) == 64 &&
                elfhdr[0]==0x7f && elfhdr[1]=='E' && elfhdr[2]=='L' && elfhdr[3]=='F')
                is_elf = true;
            close(efd);
        }
        if (is_elf) {
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
                mvwprintw(win, row, x, "━━ Binary / ELF ");
                wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
            } ADVANCE();
            /* ELF class */
            const char *elf_class = elfhdr[4]==1?"32-bit":elfhdr[4]==2?"64-bit":"unknown";
            const char *elf_endian = elfhdr[5]==1?"LE":elfhdr[5]==2?"BE":"?";
            const char *elf_osabi_names[] = {"System V","HP-UX","NetBSD","Linux","GNU/Hurd",
                "?","Solaris","AIX","IRIX","FreeBSD","Tru64","Modesto","OpenBSD","OpenVMS","NSK","AROS"};
            int osabi = elfhdr[7];
            const char *osabi_str = (osabi < 16) ? elf_osabi_names[osabi] : "Other";
            /* e_type at offset 16 (2 bytes LE) */
            uint16_t e_type = (uint16_t)(elfhdr[16] | (elfhdr[17]<<8));
            const char *etype_str = e_type==1?"Relocatable":e_type==2?"Executable":
                                    e_type==3?"Shared lib":e_type==4?"Core dump":"Unknown";
            /* e_machine at offset 18 */
            uint16_t e_mach = (uint16_t)(elfhdr[18] | (elfhdr[19]<<8));
            const char *arch_str = e_mach==0x3e?"x86-64":e_mach==0x28?"ARM":
                                   e_mach==0xb7?"AArch64":e_mach==0x03?"x86":
                                   e_mach==0x08?"MIPS":e_mach==0xf3?"RISC-V":"other";
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Arch  : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                wattron(win, COLOR_PAIR(FI_CP_VAL));
                mvwprintw(win, row, x+8, "%s %s %s", arch_str, elf_class, elf_endian);
                wattroff(win, COLOR_PAIR(FI_CP_VAL));
            } ADVANCE();
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Type  : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                wattron(win, COLOR_PAIR(FI_CP_VAL));
                mvwprintw(win, row, x+8, "%s (OS: %s)", etype_str, osabi_str);
                wattroff(win, COLOR_PAIR(FI_CP_VAL));
            } ADVANCE();
            /* Count ELF sections */
            uint16_t e_shnum = (uint16_t)(elfhdr[60] | (elfhdr[61]<<8));
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Sects : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                wattron(win, COLOR_PAIR(FI_CP_VAL));
                mvwprintw(win, row, x+8, "%u ELF sections", (unsigned)e_shnum);
                wattroff(win, COLOR_PAIR(FI_CP_VAL));
            } ADVANCE();
            /* Check stripped via nm */
            bool stripped = true;
            FILE *nm_pipe = NULL;
            {
                char cmd[4096+32];
                snprintf(cmd, sizeof cmd, "nm -a '%s' 2>/dev/null | wc -l", path);
                nm_pipe = popen(cmd, "r");
                if (nm_pipe) {
                    int sym_count = 0;
                    if (fscanf(nm_pipe, "%d", &sym_count) == 1 && sym_count > 0)
                        stripped = false;
                    pclose(nm_pipe);
                }
            }
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Debug : "); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                int cp_s = stripped ? FI_CP_VAL_WARN : FI_CP_VAL_GOOD;
                wattron(win, COLOR_PAIR(cp_s));
                mvwprintw(win, row, x+8, "%s", stripped ? "Stripped" : "Has symbols");
                wattroff(win, COLOR_PAIR(cp_s));
            } ADVANCE();
        }
    }

    /* ══ Section: GPS / EXIF (JPEG only) ════════════════════════ */
    if (has_stat && S_ISREG(st.st_mode) && st.st_size > 12) {
        /* Check JPEG magic */
        unsigned char jbuf[4];
        int jfd = open(path, O_RDONLY);
        bool is_jpeg = false;
        if (jfd >= 0) {
            if (read(jfd, jbuf, 4) == 4 && jbuf[0]==0xFF && jbuf[1]==0xD8)
                is_jpeg = true;
            close(jfd);
        }
        if (is_jpeg) {
            /* Parse EXIF: scan for APP1 (FF E1) marker with "Exif" */
            unsigned char *exif_buf = NULL;
            size_t exif_len = 0;
            int xfd = open(path, O_RDONLY);
            if (xfd >= 0) {
                size_t fsz = (size_t)st.st_size;
                size_t scan_max = fsz < 65536 ? fsz : 65536;
                unsigned char *fbuf = malloc(scan_max);
                if (fbuf && read(xfd, fbuf, scan_max) == (ssize_t)scan_max) {
                    /* Find APP1 */
                    for (size_t si = 0; si + 10 < scan_max; si++) {
                        if (fbuf[si]==0xFF && fbuf[si+1]==0xE1) {
                            size_t seg_len = (fbuf[si+2]<<8)|fbuf[si+3];
                            if (si+4+seg_len <= scan_max &&
                                (fbuf[si+4]=='E'&&fbuf[si+5]=='x'&&fbuf[si+6]=='i'&&fbuf[si+7]=='f'&&fbuf[si+8]==0&&fbuf[si+9]==0)) {
                                exif_buf = fbuf + si + 10;
                                exif_len = seg_len - 8;
                                break;
                            }
                        }
                    }
                    if (exif_buf && exif_len > 8) {
                        /* TIFF header in EXIF */
                        bool le = (exif_buf[0]=='I');
                        #define EXIF_U16(p) (le ? ((uint16_t)(p)[0]|((uint16_t)(p)[1]<<8)) : ((uint16_t)(p)[1]|((uint16_t)(p)[0]<<8)))
                        #define EXIF_U32(p) (le ? ((uint32_t)(p)[0]|((uint32_t)(p)[1]<<8)|((uint32_t)(p)[2]<<16)|((uint32_t)(p)[3]<<24)) : ((uint32_t)(p)[3]|((uint32_t)(p)[2]<<8)|((uint32_t)(p)[1]<<16)|((uint32_t)(p)[0]<<24)))
                        uint32_t ifd0_off = EXIF_U32(exif_buf+4);
                        double gps_lat=0, gps_lon=0, gps_alt=0;
                        bool has_lat=false, has_lon=false, has_alt=false;
                        char gps_lat_ref='N', gps_lon_ref='E';
                        /* Scan IFD0 for GPS IFD pointer (tag 0x8825) */
                        if (ifd0_off + 2 <= exif_len) {
                            uint16_t nent = EXIF_U16(exif_buf + ifd0_off);
                            uint32_t gps_ifd_off = 0;
                            for (uint16_t ei = 0; ei < nent && ifd0_off+2+ei*12+12 <= exif_len; ei++) {
                                uint8_t *e = exif_buf + ifd0_off + 2 + ei*12;
                                uint16_t tag = EXIF_U16(e);
                                if (tag == 0x8825) { gps_ifd_off = EXIF_U32(e+8); break; }
                            }
                            /* Parse GPS IFD */
                            if (gps_ifd_off && gps_ifd_off+2 <= exif_len) {
                                uint16_t gn = EXIF_U16(exif_buf + gps_ifd_off);
                                for (uint16_t gi = 0; gi < gn && gps_ifd_off+2+gi*12+12 <= exif_len; gi++) {
                                    uint8_t *ge = exif_buf + gps_ifd_off + 2 + gi*12;
                                    uint16_t gtag = EXIF_U16(ge);
                                    uint32_t voff = EXIF_U32(ge+8);
                                    /* GPS tags: 1=LatRef, 2=Lat, 3=LonRef, 4=Lon, 5=AltRef, 6=Alt */
                                    if (gtag == 1 && voff < exif_len) { gps_lat_ref = (char)exif_buf[voff]; }
                                    else if (gtag == 3 && voff < exif_len) { gps_lon_ref = (char)exif_buf[voff]; }
                                    else if ((gtag == 2 || gtag == 4) && voff+24 <= exif_len) {
                                        /* 3 rationals: deg, min, sec */
                                        double deg = (double)EXIF_U32(exif_buf+voff)   / (double)EXIF_U32(exif_buf+voff+4);
                                        double min = (double)EXIF_U32(exif_buf+voff+8) / (double)EXIF_U32(exif_buf+voff+12);
                                        double sec = (double)EXIF_U32(exif_buf+voff+16)/ (double)EXIF_U32(exif_buf+voff+20);
                                        double val = deg + min/60.0 + sec/3600.0;
                                        if (gtag==2) { gps_lat=val; has_lat=true; }
                                        else         { gps_lon=val; has_lon=true; }
                                    } else if (gtag == 6 && voff+8 <= exif_len) {
                                        uint32_t anum = EXIF_U32(exif_buf+voff);
                                        uint32_t aden = EXIF_U32(exif_buf+voff+4);
                                        if (aden) { gps_alt = (double)anum/aden; has_alt=true; }
                                    }
                                }
                            }
                        }
                        if (has_lat || has_lon) {
                            if (gps_lat_ref=='S') gps_lat = -gps_lat;
                            if (gps_lon_ref=='W') gps_lon = -gps_lon;
                            if (ROW_VIS) {
                                wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
                                mvwprintw(win, row, x, "━━ GPS / EXIF ");
                                wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
                            } ADVANCE();
                            if (ROW_VIS) {
                                wattron(win, COLOR_PAIR(FI_CP_KEY));
                                mvwprintw(win, row, x, "Lat   :"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                                wattron(win, COLOR_PAIR(FI_CP_VAL_GOOD));
                                mvwprintw(win, row, x+8, "%.6f %c", fabs(gps_lat), gps_lat>=0?'N':'S');
                                wattroff(win, COLOR_PAIR(FI_CP_VAL_GOOD));
                            } ADVANCE();
                            if (ROW_VIS) {
                                wattron(win, COLOR_PAIR(FI_CP_KEY));
                                mvwprintw(win, row, x, "Lon   :"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                                wattron(win, COLOR_PAIR(FI_CP_VAL_GOOD));
                                mvwprintw(win, row, x+8, "%.6f %c", fabs(gps_lon), gps_lon>=0?'E':'W');
                                wattroff(win, COLOR_PAIR(FI_CP_VAL_GOOD));
                            } ADVANCE();
                            if (has_alt) {
                                if (ROW_VIS) {
                                    wattron(win, COLOR_PAIR(FI_CP_KEY));
                                    mvwprintw(win, row, x, "Alt   :"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                                    wattron(win, COLOR_PAIR(FI_CP_VAL));
                                    mvwprintw(win, row, x+8, "%.1f m", gps_alt);
                                    wattroff(win, COLOR_PAIR(FI_CP_VAL));
                                } ADVANCE();
                            }
                            /* Google Maps URL hint */
                            if (ROW_VIS) {
                                wattron(win, COLOR_PAIR(FI_CP_KEY));
                                mvwprintw(win, row, x, "Maps  :"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                            } ADVANCE();
                            {
                                char maps_url[128];
                                snprintf(maps_url, sizeof maps_url,
                                         "%.6f,%.6f", gps_lat, gps_lon);
                                wattron(win, COLOR_PAIR(FI_CP_ENCODING));
                                draw_wrapped(win, &vrow, scroll, win_h, x+1, w, FI_CP_ENCODING, maps_url);
                                wattroff(win, COLOR_PAIR(FI_CP_ENCODING));
                            }
                        }
                    }
                    free(fbuf);
                }
                close(xfd);
            }
        }
    }

    /* ══ Section: Forensic ═══════════════════════════════════════ */
    if (has_stat && S_ISREG(st.st_mode) && st.st_size > 0
            && st.st_size < 256*1024*1024) {
        if (ROW_VIS) {
            wattron(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
            mvwprintw(win, row, x, "━━ Forensic ");
            wattroff(win, COLOR_PAIR(FI_CP_SECTION) | A_BOLD);
        } ADVANCE();
        /* Shannon entropy */
        {
            uint64_t freq[256] = {0};
            int efd2 = open(path, O_RDONLY);
            long long total = 0;
            if (efd2 >= 0) {
                unsigned char ebuf[65536]; ssize_t en;
                size_t scan_limit = (size_t)(st.st_size < 4*1024*1024 ? st.st_size : 4*1024*1024);
                size_t scanned = 0;
                while (scanned < scan_limit && (en = read(efd2, ebuf, sizeof ebuf)) > 0) {
                    for (ssize_t ei = 0; ei < en; ei++) freq[(unsigned char)ebuf[ei]]++;
                    scanned += (size_t)en;
                    total += en;
                }
                close(efd2);
            }
            double entropy = 0.0;
            if (total > 0) {
                for (int bi = 0; bi < 256; bi++) {
                    if (freq[bi]) {
                        double p = (double)freq[bi] / (double)total;
                        entropy -= p * log2(p);
                    }
                }
            }
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Entropy:"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                /* > 7.8 = likely encrypted/compressed, > 7.2 = packed */
                int cp_ent = entropy > 7.8 ? FI_CP_VAL_BAD :
                             entropy > 7.2 ? FI_CP_VAL_WARN : FI_CP_VAL_GOOD;
                wattron(win, COLOR_PAIR(cp_ent) | A_BOLD);
                const char *ent_hint = entropy > 7.8 ? "encrypted?" :
                                       entropy > 7.2 ? "packed?"    : "normal";
                mvwprintw(win, row, x+9, "%.4f/8 (%s)", entropy, ent_hint);
                wattroff(win, COLOR_PAIR(cp_ent) | A_BOLD);
            } ADVANCE();
        }
        /* Printable strings count (quick heuristic) */
        {
            int sfd = open(path, O_RDONLY);
            long str_count = 0;
            if (sfd >= 0) {
                unsigned char sbuf[65536]; ssize_t sn;
                int run = 0;
                size_t scan_limit = (size_t)(st.st_size < 2*1024*1024 ? st.st_size : 2*1024*1024);
                size_t scanned = 0;
                while (scanned < scan_limit && (sn = read(sfd, sbuf, sizeof sbuf)) > 0) {
                    for (ssize_t si = 0; si < sn; si++) {
                        if (isprint(sbuf[si])||sbuf[si]=='	') run++;
                        else { if (run >= 4) str_count++; run = 0; }
                    }
                    scanned += (size_t)sn;
                }
                if (run >= 4) str_count++;
                close(sfd);
            }
            if (ROW_VIS) {
                wattron(win, COLOR_PAIR(FI_CP_KEY));
                mvwprintw(win, row, x, "Strings:"); wattroff(win, COLOR_PAIR(FI_CP_KEY));
                wattron(win, COLOR_PAIR(FI_CP_VAL));
                mvwprintw(win, row, x+9, "%ld printable", str_count);
                wattroff(win, COLOR_PAIR(FI_CP_VAL));
            } ADVANCE();
        }
        /* Embedded archive / polyglot detection: scan for magic sigs inside file */
        if (st.st_size > 256) {
            unsigned char *polybuf = NULL;
            size_t polymax = (size_t)(st.st_size < 1024*1024 ? st.st_size : 1024*1024);
            int pfd = open(path, O_RDONLY);
            if (pfd >= 0) {
                polybuf = malloc(polymax);
                if (polybuf && read(pfd, polybuf, polymax) == (ssize_t)polymax) {
                    int hidden_count = 0;
                    const struct { const char *name; unsigned char sig[8]; int len; } hidden_sigs[] = {
                        {"ZIP",  {0x50,0x4B,0x03,0x04}, 4},
                        {"GZIP", {0x1F,0x8B},            2},
                        {"ELF",  {0x7F,0x45,0x4C,0x46}, 4},
                        {"PDF",  {0x25,0x50,0x44,0x46}, 4},
                        {"PE",   {0x4D,0x5A},            2},
                        {NULL,   {0},                    0}
                    };
                    for (int hi = 0; hidden_sigs[hi].name; hi++) {
                        int slen = hidden_sigs[hi].len;
                        /* skip offset 0 (that's the file itself) */
                        for (size_t pi = 1; pi + (size_t)slen <= polymax; pi++) {
                            if (memcmp(polybuf+pi, hidden_sigs[hi].sig, (size_t)slen)==0) {
                                hidden_count++;
                                if (ROW_VIS) {
                                    wattron(win, COLOR_PAIR(FI_CP_VAL_BAD) | A_BOLD);
                                    mvwprintw(win, row, x, "⚠ Embedded %s @%zu",
                                              hidden_sigs[hi].name, pi);
                                    wattroff(win, COLOR_PAIR(FI_CP_VAL_BAD) | A_BOLD);
                                } ADVANCE();
                                break; /* one per type */
                            }
                        }
                    }
                    if (hidden_count == 0 && ROW_VIS) {
                        wattron(win, COLOR_PAIR(FI_CP_VAL_GOOD));
                        mvwprintw(win, row, x, "No embedded magic");
                        wattroff(win, COLOR_PAIR(FI_CP_VAL_GOOD));
                    }
                    if (hidden_count == 0) ADVANCE();
                }
                free(polybuf);
                close(pfd);
            }
        }
    }

    wnoutrefresh(win);
}