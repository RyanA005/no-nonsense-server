#include "filesystem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FS_MAX_NODES 64
#define FS_MAX_COMP 48
#define FS_MAX_NAME 64
#define FS_MAX_FILE (512 * 1024)

static struct spooky_node g_nodes[FS_MAX_NODES];
static size_t g_count;

const struct spooky_node *fs_lookup(const char *path) {
    size_t i;

    if (path == NULL) {
        return NULL;
    }
    for (i = 0; i < g_count; i++) {
        if (strcmp(g_nodes[i].path, path) == 0) {
            return &g_nodes[i];
        }
    }
    return NULL;
}

static int valid_virtual_path(const char *path) {
    const char *p;

    if (path == NULL || path[0] != '/' || strlen(path) >= SPOOKY_PATH_MAX) {
        return 0;
    }
    if (strcmp(path, "/") == 0) {
        return 1;
    }
    p = path + 1;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t n = slash == NULL ? strlen(p) : (size_t)(slash - p);
        if (n == 0 || n >= FS_MAX_NAME) {
            return 0;
        }
        if ((n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.')) {
            return 0;
        }
        if (slash == NULL) {
            break;
        }
        p = slash + 1;
        if (*p == '\0') {
            return 0;
        }
    }
    return 1;
}

static int read_host_file(const char *path, uint8_t **data_out, size_t *len_out, char *err, size_t errlen) {
    FILE *file;
    long sz;
    uint8_t *data;

    file = fopen(path, "rb");
    if (file == NULL) {
        snprintf(err, errlen, "cannot open fixture %s", path);
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        snprintf(err, errlen, "cannot size fixture %s", path);
        return -1;
    }
    sz = ftell(file);
    if (sz < 0 || sz > FS_MAX_FILE) {
        fclose(file);
        snprintf(err, errlen, "fixture too large %s", path);
        return -1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        snprintf(err, errlen, "cannot rewind fixture %s", path);
        return -1;
    }
    data = malloc((size_t)sz + 1);
    if (data == NULL) {
        fclose(file);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    if (sz > 0 && fread(data, 1, (size_t)sz, file) != (size_t)sz) {
        free(data);
        fclose(file);
        snprintf(err, errlen, "short read %s", path);
        return -1;
    }
    data[sz] = 0;
    fclose(file);
    *data_out = data;
    *len_out = (size_t)sz;
    return 0;
}

static int add_node(char kind, unsigned mode, unsigned uid, const char *path,
                    const char *data_dir, char *err, size_t errlen) {
    struct spooky_node *node;
    char host_path[4096];
    int wrote;

    if (g_count >= FS_MAX_NODES) {
        snprintf(err, errlen, "too many filesystem nodes");
        return -1;
    }
    if ((kind != 'D' && kind != 'F') || !valid_virtual_path(path)) {
        snprintf(err, errlen, "bad manifest path %s", path == NULL ? "" : path);
        return -1;
    }
    if (fs_lookup(path) != NULL) {
        snprintf(err, errlen, "duplicate path %s", path);
        return -1;
    }
    if (mode > 0777) {
        snprintf(err, errlen, "bad mode for %s", path);
        return -1;
    }

    node = &g_nodes[g_count];
    memset(node, 0, sizeof *node);
    memcpy(node->path, path, strlen(path) + 1);
    node->owner_uid = uid;
    node->mode = (uint16_t)mode;
    node->is_directory = kind == 'D';
    if (node->is_directory) {
        g_count++;
        return 0;
    }

    wrote = snprintf(host_path, sizeof host_path, "%s/root%s", data_dir, path);
    if (wrote < 0 || (size_t)wrote >= sizeof host_path) {
        snprintf(err, errlen, "fixture path truncated");
        return -1;
    }
    if (read_host_file(host_path, &node->data, &node->size, err, errlen) < 0) {
        return -1;
    }
    g_count++;
    return 0;
}

static int set_flag(const char *flag, char *err, size_t errlen) {
    struct spooky_node *node = NULL;
    size_t i;
    size_t flen;
    size_t total;
    uint8_t *data;

    for (i = 0; i < g_count; i++) {
        if (strcmp(g_nodes[i].path, "/home/admin/flag.txt") == 0) {
            node = &g_nodes[i];
            break;
        }
    }
    if (node == NULL || node->is_directory) {
        snprintf(err, errlen, "flag node missing from manifest");
        return -1;
    }
    flen = strlen(flag);
    if (flen == 0 || flen > 1024) {
        snprintf(err, errlen, "flag length is invalid");
        return -1;
    }
    total = flen;
    if (flag[flen - 1] != '\n') {
        total++;
    }
    data = malloc(total + 1);
    if (data == NULL) {
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    memcpy(data, flag, flen);
    if (total != flen) {
        data[flen] = '\n';
    }
    data[total] = 0;
    free(node->data);
    node->data = data;
    node->size = total;
    return 0;
}

int fs_load(const char *data_dir, const char *flag, char *err, size_t errlen) {
    char manifest_path[4096];
    FILE *file;
    char line[512];
    int wrote;

    g_count = 0;
    wrote = snprintf(manifest_path, sizeof manifest_path, "%s/manifest.txt", data_dir);
    if (wrote < 0 || (size_t)wrote >= sizeof manifest_path) {
        snprintf(err, errlen, "data directory path is too long");
        return -1;
    }
    file = fopen(manifest_path, "r");
    if (file == NULL) {
        snprintf(err, errlen, "cannot open %s", manifest_path);
        return -1;
    }

    while (fgets(line, sizeof line, file) != NULL) {
        char kind;
        unsigned mode = 0;
        unsigned uid = 0;
        char path[SPOOKY_PATH_MAX];
        char extra[8];
        size_t len = strlen(line);

        if (len == 0 || line[0] == '#' || line[0] == '\n') {
            continue;
        }
        if (len + 1 == sizeof line && line[len - 1] != '\n') {
            fclose(file);
            snprintf(err, errlen, "manifest line too long");
            return -1;
        }
        extra[0] = '\0';
        if (sscanf(line, " %c %o %u %255s %7s", &kind, &mode, &uid, path, extra) != 4) {
            fclose(file);
            snprintf(err, errlen, "bad manifest line");
            return -1;
        }
        if (add_node(kind, mode, uid, path, data_dir, err, errlen) < 0) {
            fclose(file);
            return -1;
        }
    }
    fclose(file);
    if (fs_lookup("/") == NULL) {
        snprintf(err, errlen, "virtual root missing");
        return -1;
    }
    return set_flag(flag, err, errlen);
}

static int can_read(const struct spooky_node *node, uint32_t uid) {
    if (uid == 0 || uid == node->owner_uid) {
        if (uid == 0) {
            return 1;
        }
        return (node->mode & 0400) != 0;
    }
    return (node->mode & 0004) != 0;
}

static int can_search(const struct spooky_node *node, uint32_t uid) {
    if (!node->is_directory) {
        return 0;
    }
    if (uid == 0) {
        return 1;
    }
    if (uid == node->owner_uid) {
        return (node->mode & 0100) != 0;
    }
    return (node->mode & 0001) != 0;
}

static void pop_path(char *path) {
    char *slash;

    if (strcmp(path, "/") == 0) {
        return;
    }
    slash = strrchr(path, '/');
    if (slash == NULL || slash == path) {
        path[0] = '/';
        path[1] = '\0';
        return;
    }
    *slash = '\0';
}

static int push_path(char *path, size_t path_sz, const char *name) {
    size_t n = strlen(path);
    size_t m = strlen(name);

    if (m == 0 || m >= FS_MAX_NAME) {
        return -1;
    }
    if (strcmp(path, "/") == 0) {
        if (1 + m >= path_sz) {
            return -1;
        }
        path[0] = '/';
        memcpy(path + 1, name, m + 1);
        return 0;
    }
    if (n + 1 + m >= path_sz) {
        return -1;
    }
    path[n] = '/';
    memcpy(path + n + 1, name, m + 1);
    return 0;
}

static int apply_require(const struct spooky_node *node, uint32_t uid, int require) {
    if (require == 's') {
        return FS_OK;
    }
    if (require == 'r') {
        if (node->is_directory) {
            return FS_IS_DIR;
        }
        return can_read(node, uid) ? FS_OK : FS_DENIED;
    }
    if (require == 'x') {
        if (!node->is_directory) {
            return FS_NOT_DIR;
        }
        return can_search(node, uid) ? FS_OK : FS_DENIED;
    }
    if (require == 'l') {
        if (!node->is_directory) {
            return FS_NOT_DIR;
        }
        if (!can_search(node, uid) || !can_read(node, uid)) {
            return FS_DENIED;
        }
        return FS_OK;
    }
    return FS_BAD_PATH;
}

int fs_visit(const char *cwd, const char *input, uint32_t uid, int require,
             char *out_path, size_t out_sz, const struct spooky_node **node_out) {
    char path[SPOOKY_PATH_MAX];
    char comps[FS_MAX_COMP][FS_MAX_NAME];
    int ncomp = 0;
    int i;
    const char *cursor;
    int absolute;

    if (node_out != NULL) {
        *node_out = NULL;
    }
    if (cwd == NULL || input == NULL || out_path == NULL || out_sz < 2) {
        return FS_BAD_PATH;
    }
    if (strlen(input) > 255 || strlen(cwd) >= SPOOKY_PATH_MAX) {
        return FS_BAD_PATH;
    }

    absolute = input[0] == '/';
    if (absolute) {
        memcpy(path, "/", 2);
    } else {
        memcpy(path, cwd, strlen(cwd) + 1);
    }

    cursor = input;
    while (*cursor) {
        char name[FS_MAX_NAME];
        size_t n = 0;

        if (*cursor == '/') {
            cursor++;
            continue;
        }
        while (cursor[n] != '\0' && cursor[n] != '/') {
            if (n + 1 >= FS_MAX_NAME) {
                return FS_BAD_PATH;
            }
            name[n] = cursor[n];
            n++;
        }
        name[n] = '\0';
        cursor += n;
        if (n == 0) {
            continue;
        }
        if (ncomp >= FS_MAX_COMP) {
            return FS_BAD_PATH;
        }
        memcpy(comps[ncomp], name, n + 1);
        ncomp++;
    }

    for (i = 0; i < ncomp; i++) {
        int last = i + 1 == ncomp;
        const struct spooky_node *current = fs_lookup(path);

        if (current == NULL) {
            return FS_NOT_FOUND;
        }
        if (strcmp(comps[i], ".") == 0) {
            continue;
        }
        /* Search permission is required to resolve every component, including "..". */
        if (!can_search(current, uid)) {
            return FS_DENIED;
        }
        if (strcmp(comps[i], "..") == 0) {
            pop_path(path);
            continue;
        }
        if (push_path(path, sizeof path, comps[i]) < 0) {
            return FS_BAD_PATH;
        }
        if (fs_lookup(path) == NULL) {
            return FS_NOT_FOUND;
        }
        if (!last && !fs_lookup(path)->is_directory) {
            return FS_NOT_DIR;
        }
    }

    {
        const struct spooky_node *node = fs_lookup(path);
        int rc;

        if (node == NULL) {
            return FS_NOT_FOUND;
        }
        rc = apply_require(node, uid, require);
        if (strlen(path) + 1 > out_sz) {
            return FS_BAD_PATH;
        }
        memcpy(out_path, path, strlen(path) + 1);
        if (node_out != NULL) {
            *node_out = node;
        }
        return rc;
    }
}

static int child_name(const char *dir, const char *path, char *name, size_t name_sz) {
    size_t dlen = strlen(dir);
    const char *rest;
    const char *slash;

    if (strcmp(dir, "/") == 0) {
        if (path[0] != '/' || path[1] == '\0' || strchr(path + 1, '/') != NULL) {
            return 0;
        }
        if (strlen(path + 1) + 1 > name_sz) {
            return 0;
        }
        memcpy(name, path + 1, strlen(path + 1) + 1);
        return 1;
    }
    if (strncmp(path, dir, dlen) != 0 || path[dlen] != '/') {
        return 0;
    }
    rest = path + dlen + 1;
    if (*rest == '\0') {
        return 0;
    }
    slash = strchr(rest, '/');
    if (slash != NULL) {
        return 0;
    }
    if (strlen(rest) + 1 > name_sz) {
        return 0;
    }
    memcpy(name, rest, strlen(rest) + 1);
    return 1;
}

struct list_ent {
    char name[FS_MAX_NAME + 2];
};

static int cmp_ent(const void *a, const void *b) {
    const struct list_ent *ea = a;
    const struct list_ent *eb = b;
    return strcmp(ea->name, eb->name);
}

int fs_list(const char *dir, uint8_t **data_out, size_t *len_out) {
    struct list_ent ents[FS_MAX_NODES];
    size_t count = 0;
    size_t i;
    size_t total = 0;
    uint8_t *buf;
    size_t pos = 0;

    if (dir == NULL || data_out == NULL || len_out == NULL) {
        return -1;
    }
    for (i = 0; i < g_count; i++) {
        char name[FS_MAX_NAME];
        if (!child_name(dir, g_nodes[i].path, name, sizeof name)) {
            continue;
        }
        if (count >= FS_MAX_NODES) {
            return -1;
        }
        snprintf(ents[count].name, sizeof ents[count].name, "%s%s",
                 name, g_nodes[i].is_directory ? "/" : "");
        count++;
    }
    qsort(ents, count, sizeof ents[0], cmp_ent);
    for (i = 0; i < count; i++) {
        total += strlen(ents[i].name) + 1;
    }
    buf = malloc(total + 1);
    if (buf == NULL) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        size_t n = strlen(ents[i].name);
        memcpy(buf + pos, ents[i].name, n);
        pos += n;
        buf[pos++] = '\n';
    }
    buf[pos] = 0;
    *data_out = buf;
    *len_out = pos;
    return 0;
}
