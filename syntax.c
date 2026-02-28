#include "abyss.h"
#include <string.h>
#include <ctype.h>

/* ─── Keyword tables ─────────────────────────────────────────── */
static const char *kw_c[] = {
    "auto","break","case","continue","default","do","else","enum",
    "extern","for","goto","if","inline","register","return","sizeof",
    "static","struct","switch","typedef","union","while","volatile",
    "_Bool","_Complex","_Imaginary","NULL","true","false",NULL
};
static const char *ty_c[] = {
    "int","char","float","double","long","short","unsigned","signed",
    "void","size_t","uint8_t","uint16_t","uint32_t","uint64_t",
    "int8_t","int16_t","int32_t","int64_t","bool","FILE","ptrdiff_t",
    "ssize_t","off_t","pid_t","pthread_t",NULL
};
static const char *kw_cpp[] = {
    "auto","break","case","catch","class","const","constexpr",
    "continue","default","delete","do","else","enum","explicit",
    "extern","for","friend","goto","if","inline","namespace","new",
    "noexcept","nullptr","operator","override","private","protected",
    "public","return","sizeof","static","struct","switch","template",
    "this","throw","try","typedef","union","using","virtual","while",
    "volatile","true","false","nullptr",NULL
};
static const char *ty_cpp[] = {
    "int","char","float","double","long","short","unsigned","signed",
    "void","bool","auto","string","vector","map","set","list","deque",
    "pair","tuple","shared_ptr","unique_ptr","weak_ptr","size_t",NULL
};
static const char *kw_py[] = {
    "False","None","True","and","as","assert","async","await","break",
    "class","continue","def","del","elif","else","except","finally",
    "for","from","global","if","import","in","is","lambda","nonlocal",
    "not","or","pass","raise","return","try","while","with","yield",NULL
};
static const char *ty_py[] = {
    "int","str","float","bool","list","dict","tuple","set","bytes",
    "object","type","super","self","cls",NULL
};
static const char *kw_sh[] = {
    "if","then","else","elif","fi","for","while","do","done","case",
    "esac","function","in","return","exit","echo","local","export",
    "readonly","shift","source","alias","unset","set","test",NULL
};
static const char *kw_js[] = {
    "break","case","catch","class","const","continue","debugger",
    "default","delete","do","else","export","extends","finally","for",
    "function","if","import","in","instanceof","let","new","return",
    "static","super","switch","this","throw","try","typeof","var",
    "void","while","with","yield","async","await","of","true","false",
    "null","undefined",NULL
};
static const char *kw_sql[] = {
    "SELECT","FROM","WHERE","JOIN","INNER","LEFT","RIGHT","OUTER","ON",
    "GROUP","BY","ORDER","HAVING","INSERT","INTO","VALUES","UPDATE",
    "SET","DELETE","CREATE","TABLE","DROP","ALTER","INDEX","PRIMARY",
    "KEY","FOREIGN","REFERENCES","NOT","NULL","UNIQUE","DEFAULT","AS",
    "AND","OR","IN","LIKE","BETWEEN","EXISTS","DISTINCT","LIMIT",
    "OFFSET","UNION","ALL","CASE","WHEN","THEN","ELSE","END","WITH",NULL
};
static const char *kw_cs[] = {
    "abstract","as","base","bool","break","byte","case","catch","char",
    "checked","class","const","continue","decimal","default","delegate",
    "do","double","else","enum","event","explicit","extern","false",
    "finally","fixed","float","for","foreach","goto","if","implicit",
    "in","int","interface","internal","is","lock","long","namespace",
    "new","null","object","operator","out","override","params",
    "private","protected","public","readonly","ref","return","sbyte",
    "sealed","short","sizeof","stackalloc","static","string","struct",
    "switch","this","throw","true","try","typeof","uint","ulong",
    "unchecked","unsafe","ushort","using","var","virtual","void",
    "volatile","while",NULL
};
static const char *kw_asm[] = {
    "mov","push","pop","call","ret","jmp","je","jne","jz","jnz",
    "jl","jle","jg","jge","cmp","test","add","sub","mul","div",
    "imul","idiv","and","or","xor","not","neg","inc","dec","lea",
    "nop","int","syscall","sysenter","leave","enter","hlt","sti",
    "cli","rep","repe","repne","movs","lods","stos","cmps","scas",
    "db","dw","dd","dq","resb","resw","resd","resq","equ","section",
    "global","extern","bits","org",NULL
};

static bool kw_match(const char **table, const char *s, int len) {
    for (int i = 0; table[i]; i++) {
        if ((int)strlen(table[i]) == len && memcmp(table[i], s, len) == 0)
            return true;
    }
    return false;
}

Language lang_from_ext(const char *ext) {
    if (!ext) return LANG_C;
    if (strcmp(ext,".c")==0||strcmp(ext,".h")==0) return LANG_C;
    if (strcmp(ext,".cpp")==0||strcmp(ext,".cc")==0||strcmp(ext,".hpp")==0) return LANG_CPP;
    if (strcmp(ext,".py")==0)   return LANG_PY;
    if (strcmp(ext,".sh")==0)   return LANG_SH;
    if (strcmp(ext,".js")==0)   return LANG_JS;
    if (strcmp(ext,".json")==0) return LANG_JSON;
    if (strcmp(ext,".sql")==0)  return LANG_SQL;
    if (strcmp(ext,".asm")==0||strcmp(ext,".s")==0) return LANG_ASM;
    if (strcmp(ext,".html")==0||strcmp(ext,".htm")==0) return LANG_HTML;
    if (strcmp(ext,".css")==0)  return LANG_CSS;
    if (strcmp(ext,".php")==0)  return LANG_PHP;
    if (strcmp(ext,".cs")==0)   return LANG_CS;
    return LANG_NONE;
}

/* ─── State machine lexer ────────────────────────────────────── */

/* lex_state: 0=normal, 1=block comment, 2=string, 3=char, 4=raw string */
typedef struct { int state; } LexState;

static void lex_line_c_like(
    const char *line, int len,
    LexState *ls, TokenType *out,
    Language lang, bool is_cpp)
{
    const char **kws = is_cpp ? kw_cpp : kw_c;
    const char **tys = is_cpp ? ty_cpp : ty_c;

    int i = 0;
    while (i < len) {
        /* block comment continuation */
        if (ls->state == 1) {
            int start = i;
            while (i < len) {
                if (i+1 < len && line[i]=='*' && line[i+1]=='/') {
                    out[i] = out[i+1] = TOK_COMMENT;
                    i += 2; ls->state = 0; goto cont;
                }
                out[i++] = TOK_COMMENT;
            }
            (void)start;
            goto cont;
        }
        /* string continuation */
        if (ls->state == 2) {
            while (i < len) {
                out[i] = TOK_STRING;
                if (line[i] == '\\') { i++; if (i<len) out[i++]=TOK_STRING; continue; }
                if (line[i++] == '"') { ls->state=0; break; }
            }
            goto cont;
        }
        /* char continuation */
        if (ls->state == 3) {
            while (i < len) {
                out[i] = TOK_CHAR;
                if (line[i] == '\\') { i++; if (i<len) out[i++]=TOK_CHAR; continue; }
                if (line[i++] == '\'') { ls->state=0; break; }
            }
            goto cont;
        }

        char c = line[i];

        /* line comment */
        if (c=='/' && i+1<len && line[i+1]=='/') {
            while (i<len) out[i++]=TOK_COMMENT;
            goto cont;
        }
        /* block comment start */
        if (c=='/' && i+1<len && line[i+1]=='*') {
            out[i++]=TOK_COMMENT; out[i++]=TOK_COMMENT;
            ls->state=1;
            goto cont;
        }
        /* preprocessor */
        if (c=='#' && i==0) {
            while (i<len) out[i++]=TOK_PREPROC;
            goto cont;
        }
        /* string */
        if (c=='"') {
            out[i++]=TOK_STRING; ls->state=2;
            goto cont;
        }
        /* char */
        if (c=='\'') {
            out[i++]=TOK_CHAR; ls->state=3;
            goto cont;
        }
        /* number */
        if (isdigit((unsigned char)c) || (c=='0' && i+1<len && (line[i+1]=='x'||line[i+1]=='X'))) {
            while (i<len && (isalnum((unsigned char)line[i])||line[i]=='.'))
                out[i++]=TOK_NUMBER;
            goto cont;
        }
        /* identifier / keyword */
        if (isalpha((unsigned char)c)||c=='_') {
            int start=i;
            while (i<len && (isalnum((unsigned char)line[i])||line[i]=='_')) i++;
            int wlen=i-start;
            TokenType tt=TOK_IDENT;
            if (kw_match(kws, line+start, wlen)) tt=TOK_KEYWORD;
            else if (kw_match(tys, line+start, wlen)) tt=TOK_TYPE;
            for(int j=start;j<i;j++) out[j]=tt;
            goto cont;
        }
        /* operators */
        if (strchr("+-*/%=<>!&|^~?:;,.{}[]()@",c))
            { out[i++]=TOK_OPERATOR; goto cont; }

        out[i++]=TOK_NORMAL;
        cont:;
    }
}

static void lex_line_python(const char *line, int len, LexState *ls, TokenType *out) {
    /* triple-quoted strings: state 5 = triple " state 6 = triple ' */
    int i=0;
    while (i<len) {
        if (ls->state==5) {
            while (i<len) {
                out[i]=TOK_STRING;
                if (i+2<len && line[i]=='"'&&line[i+1]=='"'&&line[i+2]=='"') {
                    out[i+1]=out[i+2]=TOK_STRING; i+=3; ls->state=0; break;
                }
                i++;
            }
            continue;
        }
        if (ls->state==6) {
            while (i<len) {
                out[i]=TOK_STRING;
                if (i+2<len && line[i]=='\''&&line[i+1]=='\''&&line[i+2]=='\'') {
                    out[i+1]=out[i+2]=TOK_STRING; i+=3; ls->state=0; break;
                }
                i++;
            }
            continue;
        }
        char c=line[i];
        /* comment */
        if (c=='#') { while(i<len) out[i++]=TOK_COMMENT; break; }
        /* triple strings */
        if (i+2<len && c=='"'&&line[i+1]=='"'&&line[i+2]=='"') {
            out[i]=out[i+1]=out[i+2]=TOK_STRING; i+=3; ls->state=5; continue;
        }
        if (i+2<len && c=='\''&&line[i+1]=='\''&&line[i+2]=='\'') {
            out[i]=out[i+1]=out[i+2]=TOK_STRING; i+=3; ls->state=6; continue;
        }
        /* simple string */
        if (c=='"'||c=='\'') {
            char delim=c; out[i++]=TOK_STRING;
            while (i<len) {
                out[i]=TOK_STRING;
                if (line[i]=='\\') { i++; if(i<len) out[i++]=TOK_STRING; continue; }
                if (line[i++]==delim) break;
            }
            continue;
        }
        /* number */
        if (isdigit((unsigned char)c)) {
            while(i<len && (isalnum((unsigned char)line[i])||line[i]=='.')) out[i++]=TOK_NUMBER;
            continue;
        }
        /* identifier */
        if (isalpha((unsigned char)c)||c=='_') {
            int start=i;
            while(i<len&&(isalnum((unsigned char)line[i])||line[i]=='_')) i++;
            int wl=i-start;
            TokenType tt=TOK_IDENT;
            if (kw_match(kw_py, line+start, wl)) tt=TOK_KEYWORD;
            else if (kw_match(ty_py, line+start, wl)) tt=TOK_TYPE;
            for(int j=start;j<i;j++) out[j]=tt;
            continue;
        }
        if (strchr("+-*/%=<>!&|^~?:;,.{}[]()@",c)) out[i++]=TOK_OPERATOR;
        else out[i++]=TOK_NORMAL;
    }
}

static void lex_line_sh(const char *line, int len, LexState *ls, TokenType *out) {
    (void)ls;
    int i=0;
    while (i<len) {
        char c=line[i];
        if (c=='#') { while(i<len) out[i++]=TOK_COMMENT; break; }
        if (c=='"'||c=='\'') {
            char d=c; out[i++]=TOK_STRING;
            while(i<len) {
                out[i]=TOK_STRING;
                if(line[i]=='\\'){i++;if(i<len)out[i++]=TOK_STRING;continue;}
                if(line[i++]==d) break;
            }
            continue;
        }
        if (isdigit((unsigned char)c)) { while(i<len&&isdigit((unsigned char)line[i])) out[i++]=TOK_NUMBER; continue; }
        if (isalpha((unsigned char)c)||c=='_') {
            int s=i;
            while(i<len&&(isalnum((unsigned char)line[i])||line[i]=='_'||line[i]=='-')) i++;
            int wl=i-s;
            TokenType tt=kw_match(kw_sh,line+s,wl)?TOK_KEYWORD:TOK_IDENT;
            for(int j=s;j<i;j++) out[j]=tt;
            continue;
        }
        if (c=='$') { out[i++]=TOK_PREPROC; continue; }
        out[i++]=TOK_NORMAL;
    }
}

static void lex_line_sql(const char *line, int len, LexState *ls, TokenType *out) {
    (void)ls;
    int i=0;
    while(i<len) {
        char c=line[i];
        if (c=='-'&&i+1<len&&line[i+1]=='-') { while(i<len) out[i++]=TOK_COMMENT; break; }
        if (c=='\'') {
            out[i++]=TOK_STRING;
            while(i<len) { out[i]=TOK_STRING; if(line[i++]=='\'') break; }
            continue;
        }
        if (isdigit((unsigned char)c)) { while(i<len&&(isdigit((unsigned char)line[i])||line[i]=='.')) out[i++]=TOK_NUMBER; continue; }
        if (isalpha((unsigned char)c)||c=='_') {
            int s=i;
            while(i<len&&(isalnum((unsigned char)line[i])||line[i]=='_')) i++;
            /* uppercase for SQL matching */
            char tmp[128]={0}; int wl=i-s; if(wl>127)wl=127;
            for(int j=0;j<wl;j++) tmp[j]=toupper((unsigned char)line[s+j]);
            TokenType tt=kw_match(kw_sql,tmp,wl)?TOK_KEYWORD:TOK_IDENT;
            for(int j=s;j<i;j++) out[j]=tt;
            continue;
        }
        out[i++]=TOK_NORMAL;
    }
}

static void lex_line_asm(const char *line, int len, LexState *ls, TokenType *out) {
    (void)ls;
    int i=0;
    while(i<len) {
        char c=line[i];
        if (c==';') { while(i<len) out[i++]=TOK_COMMENT; break; }
        if (c=='\''||c=='"') {
            char d=c; out[i++]=TOK_STRING;
            while(i<len){out[i]=TOK_STRING;if(line[i++]==d)break;}
            continue;
        }
        if (c=='0'&&i+1<len&&(line[i+1]=='x'||line[i+1]=='X')) {
            while(i<len&&(isxdigit((unsigned char)line[i])||line[i]=='x'||line[i]=='X')) out[i++]=TOK_NUMBER;
            continue;
        }
        if (isdigit((unsigned char)c)) { while(i<len&&(isalnum((unsigned char)line[i])||line[i]=='.')) out[i++]=TOK_NUMBER; continue; }
        if (isalpha((unsigned char)c)||c=='_'||c=='.') {
            int s=i;
            while(i<len&&(isalnum((unsigned char)line[i])||line[i]=='_'||line[i]=='.')) i++;
            int wl=i-s;
            char tmp[64]={0}; if(wl>63)wl=63;
            for(int j=0;j<wl;j++) tmp[j]=tolower((unsigned char)line[s+j]);
            TokenType tt=kw_match(kw_asm,tmp,wl)?TOK_KEYWORD:TOK_IDENT;
            for(int j=s;j<i;j++) out[j]=tt;
            continue;
        }
        if (c=='%'||c=='$') { out[i++]=TOK_PREPROC; continue; }
        out[i++]=TOK_NORMAL;
    }
}

static void lex_line_generic(const char *line, int len, LexState *ls, TokenType *out) {
    (void)ls;
    for(int i=0;i<len;i++) out[i]=TOK_NORMAL;
}

/* ─── SynCtx ──────────────────────────────────────────────────── */

SynCtx *syn_new(Language lang) {
    SynCtx *s = calloc(1, sizeof *s);
    s->lang = lang;
    s->cap = 256;
    s->lines = calloc(s->cap, sizeof(LineAttr));
    /* calloc zeroes dirty=false — explicitly mark all slots dirty so
       syn_ensure_line computes colours on the very first render */
    for (size_t i = 0; i < s->cap; i++) s->lines[i].dirty = true;
    return s;
}

void syn_free(SynCtx *s) {
    if (!s) return;
    for (size_t i=0;i<s->count;i++) free(s->lines[i].attrs);
    free(s->lines);
    free(s);
}

void syn_mark_dirty_from(SynCtx *s, size_t line) {
    for (size_t i=line; i<s->count; i++) s->lines[i].dirty=true;
}

static void ensure_line_cap(SynCtx *s, size_t line) {
    if (line >= s->cap) {
        size_t new_cap = line + 256;
        s->lines = realloc(s->lines, new_cap * sizeof(LineAttr));
        for (size_t i=s->cap; i<new_cap; i++) {
            memset(&s->lines[i], 0, sizeof(LineAttr));
            s->lines[i].dirty = true;
        }
        s->cap = new_cap;
    }
    if (line >= s->count) {
        s->count = line + 1;
    }
}

void syn_ensure_line(SynCtx *s, size_t line, const GapBuf *g, const LineIdx *li) {
    ensure_line_cap(s, line);
    LineAttr *la = &s->lines[line];
    if (!la->dirty) return;

    size_t lcount = li_line_count(li);
    if (line >= lcount) { la->dirty=false; return; }

    size_t start = li_line_start(li, line);
    size_t end = (line+1 < lcount) ? li_line_start(li, line+1)-1 : gb_len(g);
    if (end < start) end = start;
    size_t len = end - start;

    /* Reallocate attrs if needed */
    if (len > la->len || !la->attrs) {
        free(la->attrs);
        la->attrs = malloc((len+1) * sizeof(TokenType));
    }
    la->len = len;

    /* Copy line text */
    char *tmp = malloc(len+1);
    gb_get_range(g, start, len, tmp);
    tmp[len]='\0';

    /* Inherit state from previous line */
    int in_state = (line > 0 && line <= s->count) ? s->lines[line-1].lex_state_end : 0;
    LexState ls = { .state = in_state };
    la->lex_state_start = in_state;

    /* Zero-init */
    for (size_t i=0;i<len;i++) la->attrs[i]=TOK_NORMAL;

    switch (s->lang) {
        case LANG_C:   lex_line_c_like(tmp,(int)len,&ls,la->attrs,LANG_C,false); break;
        case LANG_CPP: lex_line_c_like(tmp,(int)len,&ls,la->attrs,LANG_CPP,true); break;
        case LANG_CS:  lex_line_c_like(tmp,(int)len,&ls,la->attrs,LANG_CS,true); break;
        case LANG_JS:
        case LANG_PHP: lex_line_c_like(tmp,(int)len,&ls,la->attrs,LANG_JS,true); break;
        case LANG_PY:  lex_line_python(tmp,(int)len,&ls,la->attrs); break;
        case LANG_SH:  lex_line_sh(tmp,(int)len,&ls,la->attrs); break;
        case LANG_SQL: lex_line_sql(tmp,(int)len,&ls,la->attrs); break;
        case LANG_ASM: lex_line_asm(tmp,(int)len,&ls,la->attrs); break;
        default:       lex_line_generic(tmp,(int)len,&ls,la->attrs); break;
    }

    la->lex_state_end = ls.state;

    /* Apply search highlights */
    if (s->search_word[0]) {
        int qlen=(int)strlen(s->search_word);
        for (int i=0;i<(int)len-(qlen-1);i++) {
            if (memcmp(tmp+i, s->search_word, qlen)==0)
                for(int j=i;j<i+qlen;j++) la->attrs[j]=TOK_SEARCH;
        }
    }

    free(tmp);
    la->dirty = false;

    /* Propagate state change to next line */
    if (line+1 < s->count && s->lines[line+1].lex_state_start != ls.state)
        s->lines[line+1].dirty = true;
}