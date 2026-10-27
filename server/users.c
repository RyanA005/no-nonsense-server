#include "users.h"

#include "crypto.h"

#include <stdio.h>
#include <string.h>

#define SPOOKY_MAX_USERS 8

static struct spooky_user g_users[SPOOKY_MAX_USERS];
static size_t g_count;

size_t users_count(void) {
    return g_count;
}

const struct spooky_user *users_at(size_t index) {
    if (index >= g_count) {
        return NULL;
    }
    return &g_users[index];
}

const struct spooky_user *users_find(const char *name, size_t len) {
    size_t i;

    if (name == NULL || len == 0 || len > 32) {
        return NULL;
    }
    for (i = 0; i < g_count; i++) {
        if (strlen(g_users[i].name) == len && memcmp(g_users[i].name, name, len) == 0) {
            return &g_users[i];
        }
    }
    return NULL;
}

static int valid_name(const char *name) {
    size_t i;
    size_t n = strlen(name);

    if (n == 0 || n > 32) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

int users_load(const char *data_dir, char *err, size_t errlen) {
    char path[4096];
    FILE *file;
    char line[512];
    int wrote;

    g_count = 0;
    wrote = snprintf(path, sizeof path, "%s/users.txt", data_dir);
    if (wrote < 0 || (size_t)wrote >= sizeof path) {
        snprintf(err, errlen, "data directory path is too long");
        return -1;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        snprintf(err, errlen, "cannot open %s", path);
        return -1;
    }

    while (fgets(line, sizeof line, file) != NULL) {
        char name[33];
        char home[SPOOKY_PATH_MAX];
        char pubname[256];
        char pubpath[4096];
        unsigned uid = 0;
        struct spooky_user *user;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        if (sscanf(line, "%32s %u %255s %255s", name, &uid, home, pubname) != 4) {
            fclose(file);
            snprintf(err, errlen, "bad users line");
            return -1;
        }
        if (!valid_name(name) || home[0] != '/' || strchr(pubname, '/') != NULL) {
            fclose(file);
            snprintf(err, errlen, "bad user record for %s", name);
            return -1;
        }
        if (g_count >= SPOOKY_MAX_USERS) {
            fclose(file);
            snprintf(err, errlen, "too many users");
            return -1;
        }
        wrote = snprintf(pubpath, sizeof pubpath, "%s/%s", data_dir, pubname);
        if (wrote < 0 || (size_t)wrote >= sizeof pubpath) {
            fclose(file);
            snprintf(err, errlen, "public key path too long");
            return -1;
        }
        user = &g_users[g_count];
        memset(user, 0, sizeof *user);
        memcpy(user->name, name, strlen(name) + 1);
        user->uid = uid;
        memcpy(user->home, home, strlen(home) + 1);
        user->pubkey = spooky_load_public_key(pubpath);
        if (user->pubkey == NULL) {
            fclose(file);
            snprintf(err, errlen, "cannot load public key %s", pubpath);
            return -1;
        }
        g_count++;
    }
    fclose(file);
    if (users_find("general", 7) == NULL || users_find("admin", 5) == NULL) {
        snprintf(err, errlen, "general and admin users are required");
        return -1;
    }
    return 0;
}
