#include "abyss.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *lang_cmd(Language lang, const char *path, char *out_cmd, size_t cmd_sz) {
    const char *ext_map[][2] = {
        /* handled by external scripts / direct commands */
        {NULL, NULL}
    };
    (void)ext_map;

    /* Mirror Python version's exact command strings */
    switch (lang) {
        case LANG_C:
            snprintf(out_cmd, cmd_sz, "gcc \"%s\" -o ./temp_bin && ./temp_bin", path);
            break;
        case LANG_CPP:
            snprintf(out_cmd, cmd_sz, "g++ \"%s\" -o ./temp_bin && ./temp_bin", path);
            break;
        case LANG_PY:
            snprintf(out_cmd, cmd_sz, "python3 \"%s\"", path);
            break;
        case LANG_SH:
            snprintf(out_cmd, cmd_sz, "bash \"%s\"", path);
            break;
        case LANG_JS:
            snprintf(out_cmd, cmd_sz, "node \"%s\"", path);
            break;
        case LANG_PHP: {
            /* Start PHP dev server + open browser */
            snprintf(out_cmd, cmd_sz,
                "php -S localhost:8080 -t \"%s\" &"
                " sleep 0.3 && xdg-open 'http://localhost:8080/%s'",
                path, path);
            break;
        }
        default:
            out_cmd[0] = '\0';
            break;
    }
    return out_cmd;
}

void run_file(const char *path, Language lang, char *out_buf, size_t out_max) {
    char cmd[8192];
    lang_cmd(lang, path, cmd, sizeof cmd);
    if (!cmd[0]) {
        snprintf(out_buf, out_max, "(No run command for this file type)");
        return;
    }

    /* Redirect stderr to stdout */
    char full_cmd[8256];
    snprintf(full_cmd, sizeof full_cmd, "(%s) 2>&1", cmd);

    FILE *fp = popen(full_cmd, "r");
    if (!fp) {
        snprintf(out_buf, out_max, "(popen failed: %s)", strerror(errno));
        return;
    }
    size_t pos = 0;
    char tmp[4096];
    while (fgets(tmp, sizeof tmp, fp) && pos < out_max - 1) {
        size_t n = strlen(tmp);
        if (pos + n >= out_max) n = out_max - pos - 1;
        memcpy(out_buf + pos, tmp, n);
        pos += n;
    }
    out_buf[pos] = '\0';
    int ret = pclose(fp);
    if (pos == 0) {
        if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0)
            snprintf(out_buf, out_max, "(Execution finished)");
        else
            snprintf(out_buf, out_max, "(Process exited with code %d)", WEXITSTATUS(ret));
    }

    /* Clean up temp binary */
    if (lang == LANG_C || lang == LANG_CPP) {
        unlink("./temp_bin");
    }
}
