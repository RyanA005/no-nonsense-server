#include "shell.h"

#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_ARGS 4
#define ARG_LEN 240

static int out_text(struct spooky_output *out, uint8_t status, const char *text) {
    size_t n = strlen(text);

    out->status = status;
    out->close_session = 0;
    out->data = malloc(n + 1);
    if (out->data == NULL) {
        return -1;
    }
    memcpy(out->data, text, n + 1);
    out->len = n;
    return 0;
}

static int out_bytes(struct spooky_output *out, uint8_t status, const uint8_t *data, size_t n) {
    out->status = status;
    out->close_session = 0;
    out->data = malloc(n + 1);
    if (out->data == NULL) {
        return -1;
    }
    if (n > 0) {
        memcpy(out->data, data, n);
    }
    out->data[n] = 0;
    out->len = n;
    return 0;
}

static int tokenize(const uint8_t *cmd, size_t len, char args[][ARG_LEN], int *argc) {
    size_t i = 0;

    *argc = 0;
    while (i < len) {
        size_t j = 0;

        while (i < len && (cmd[i] == ' ' || cmd[i] == '\t' || cmd[i] == '\n' || cmd[i] == '\r')) {
            i++;
        }
        if (i >= len) {
            break;
        }
        if (*argc >= MAX_ARGS) {
            return -1;
        }
        while (i < len && cmd[i] != ' ' && cmd[i] != '\t' && cmd[i] != '\n' && cmd[i] != '\r') {
            if (cmd[i] == '\0') {
                return -2;
            }
            if (j + 1 >= ARG_LEN) {
                return -1;
            }
            args[*argc][j++] = (char)cmd[i++];
        }
        args[*argc][j] = '\0';
        (*argc)++;
    }
    return 0;
}

static int format_fs_error(struct spooky_output *out, const char *command, const char *path, int rc) {
    char buf[512];

    if (rc == FS_DENIED) {
        snprintf(buf, sizeof buf, "%s: %s: Permission denied\n", command, path);
        return out_text(out, SPOOKY_EXEC_DENIED, buf);
    }
    if (rc == FS_NOT_FOUND) {
        snprintf(buf, sizeof buf, "%s: %s: No such file or directory\n", command, path);
        return out_text(out, SPOOKY_EXEC_ERR, buf);
    }
    if (rc == FS_IS_DIR) {
        snprintf(buf, sizeof buf, "%s: %s: Is a directory\n", command, path);
        return out_text(out, SPOOKY_EXEC_ERR, buf);
    }
    if (rc == FS_NOT_DIR) {
        snprintf(buf, sizeof buf, "%s: %s: Not a directory\n", command, path);
        return out_text(out, SPOOKY_EXEC_ERR, buf);
    }
    snprintf(buf, sizeof buf, "%s: %s: Invalid path\n", command, path);
    return out_text(out, SPOOKY_EXEC_ERR, buf);
}

static int cmd_help(struct spooky_output *out) {
    return out_text(out, SPOOKY_EXEC_OK,
                    "SP00KY shell\n"
                    "  help\n"
                    "  whoami\n"
                    "  id\n"
                    "  pwd\n"
                    "  ls [path]\n"
                    "  cd [path]\n"
                    "  cat <path>\n"
                    "  stat <path>\n"
                    "  date\n"
                    "  uname\n"
                    "  exit\n");
}

static int cmd_whoami(struct spooky_session *session, struct spooky_output *out) {
    char buf[64];

    snprintf(buf, sizeof buf, "%s\n", session->username);
    return out_text(out, SPOOKY_EXEC_OK, buf);
}

static int cmd_id(struct spooky_session *session, struct spooky_output *out) {
    char buf[128];

    snprintf(buf, sizeof buf, "uid=%u(%s) gid=%u(%s) groups=%u(%s)\n",
             session->uid, session->username, session->uid, session->username,
             session->uid, session->username);
    return out_text(out, SPOOKY_EXEC_OK, buf);
}

static int cmd_pwd(struct spooky_session *session, struct spooky_output *out) {
    char buf[SPOOKY_PATH_MAX + 2];

    snprintf(buf, sizeof buf, "%s\n", session->cwd);
    return out_text(out, SPOOKY_EXEC_OK, buf);
}

static int cmd_date(struct spooky_output *out) {
    char buf[128];
    time_t now = time(NULL);
    struct tm tm;

    if (localtime_r(&now, &tm) == NULL ||
        strftime(buf, sizeof buf, "%a %b %e %H:%M:%S %Z %Y\n", &tm) == 0) {
        return out_text(out, SPOOKY_EXEC_ERR, "date: unavailable\n");
    }
    return out_text(out, SPOOKY_EXEC_OK, buf);
}

static int cmd_uname(struct spooky_output *out) {
    return out_text(out, SPOOKY_EXEC_OK, "SP00KY spooky 1.0.0-spooky #1 SMP PREEMPT SP00KY x86_64\n");
}

static int cmd_ls(struct spooky_session *session, const char *path, struct spooky_output *out) {
    char resolved[SPOOKY_PATH_MAX];
    const struct spooky_node *node = NULL;
    const char *input = path == NULL ? session->cwd : path;
    int rc = fs_visit(session->cwd, input, session->uid, 'l', resolved, sizeof resolved, &node);

    if (rc == FS_NOT_DIR && node != NULL && !node->is_directory) {
        char buf[SPOOKY_PATH_MAX + 2];
        const char *base = strrchr(resolved, '/');
        base = (base == NULL || base[1] == '\0') ? resolved : base + 1;
        snprintf(buf, sizeof buf, "%s\n", base);
        return out_text(out, SPOOKY_EXEC_OK, buf);
    }
    if (rc != FS_OK) {
        return format_fs_error(out, "ls", path == NULL ? session->cwd : path, rc);
    }

    {
        uint8_t *listed = NULL;
        size_t listed_len = 0;
        int listed_rc = fs_list(resolved, &listed, &listed_len);
        int text_rc;

        if (listed_rc < 0) {
            return out_text(out, SPOOKY_EXEC_ERR, "ls: internal error\n");
        }
        text_rc = out_bytes(out, SPOOKY_EXEC_OK, listed, listed_len);
        free(listed);
        return text_rc;
    }
}

static int cmd_cd(struct spooky_session *session, const char *path, struct spooky_output *out) {
    char resolved[SPOOKY_PATH_MAX];
    const struct spooky_node *node = NULL;
    const char *input = path == NULL ? session->home : path;
    int rc = fs_visit(session->cwd, input, session->uid, 'x', resolved, sizeof resolved, &node);

    if (rc != FS_OK) {
        return format_fs_error(out, "cd", path == NULL ? session->home : path, rc);
    }
    memcpy(session->cwd, resolved, strlen(resolved) + 1);
    return out_text(out, SPOOKY_EXEC_OK, "");
}

static int cmd_cat(struct spooky_session *session, const char *path, struct spooky_output *out) {
    char resolved[SPOOKY_PATH_MAX];
    const struct spooky_node *node = NULL;
    int rc = fs_visit(session->cwd, path, session->uid, 'r', resolved, sizeof resolved, &node);
    size_t n;
    const uint8_t *data;

    if (rc != FS_OK) {
        return format_fs_error(out, "cat", path, rc);
    }
    data = node->data == NULL ? (const uint8_t *)"" : node->data;
    n = node->size;
    if (n > SPOOKY_MAX_OUTPUT) {
        char *buf = malloc(SPOOKY_MAX_OUTPUT);
        int text_rc;
        if (buf == NULL) {
            return -1;
        }
        memcpy(buf, data, SPOOKY_MAX_OUTPUT - 32);
        memcpy(buf + SPOOKY_MAX_OUTPUT - 32, "\n[output truncated]\n", 20);
        text_rc = out_bytes(out, SPOOKY_EXEC_OK, (const uint8_t *)buf, SPOOKY_MAX_OUTPUT - 32 + 20);
        free(buf);
        return text_rc;
    }
    return out_bytes(out, SPOOKY_EXEC_OK, data, n);
}

static int cmd_stat(struct spooky_session *session, const char *path, struct spooky_output *out) {
    char resolved[SPOOKY_PATH_MAX];
    const struct spooky_node *node = NULL;
    char buf[512];
    int rc = fs_visit(session->cwd, path, session->uid, 's', resolved, sizeof resolved, &node);

    if (rc != FS_OK || node == NULL) {
        return format_fs_error(out, "stat", path, rc);
    }
    snprintf(buf, sizeof buf,
             "  File: %s\n"
             "  Size: %zu\n"
             "  Mode: %04o\n"
             "  Owner: %u\n"
             "  Type: %s\n",
             node->path, node->size, node->mode & 0777, node->owner_uid,
             node->is_directory ? "directory" : "file");
    return out_text(out, SPOOKY_EXEC_OK, buf);
}

int shell_exec(struct spooky_session *session, const uint8_t *cmd, size_t cmd_len,
               struct spooky_output *out) {
    char args[MAX_ARGS][ARG_LEN];
    int argc = 0;
    int tok;

    memset(out, 0, sizeof *out);
    if (session == NULL || cmd == NULL || out == NULL) {
        return -1;
    }
    if (cmd_len > SPOOKY_MAX_COMMAND) {
        return out_text(out, SPOOKY_EXEC_ERR, "command too long\n");
    }

    tok = tokenize(cmd, cmd_len, args, &argc);
    if (tok == -2) {
        return out_text(out, SPOOKY_EXEC_ERR, "invalid command\n");
    }
    if (tok != 0) {
        return out_text(out, SPOOKY_EXEC_ERR, "invalid command\n");
    }
    if (argc == 0) {
        return out_text(out, SPOOKY_EXEC_ERR, "empty command\n");
    }

    if (strcmp(args[0], "help") == 0 && argc == 1) {
        return cmd_help(out);
    }
    if (strcmp(args[0], "whoami") == 0 && argc == 1) {
        return cmd_whoami(session, out);
    }
    if (strcmp(args[0], "id") == 0 && argc == 1) {
        return cmd_id(session, out);
    }
    if (strcmp(args[0], "pwd") == 0 && argc == 1) {
        return cmd_pwd(session, out);
    }
    if (strcmp(args[0], "date") == 0 && argc == 1) {
        return cmd_date(out);
    }
    if (strcmp(args[0], "uname") == 0 && argc == 1) {
        return cmd_uname(out);
    }
    if (strcmp(args[0], "exit") == 0 && argc == 1) {
        if (out_text(out, SPOOKY_EXEC_OK, "logout\n") < 0) {
            return -1;
        }
        out->close_session = 1;
        return 0;
    }
    if (strcmp(args[0], "ls") == 0 && (argc == 1 || argc == 2)) {
        return cmd_ls(session, argc == 2 ? args[1] : NULL, out);
    }
    if (strcmp(args[0], "cd") == 0 && (argc == 1 || argc == 2)) {
        return cmd_cd(session, argc == 2 ? args[1] : NULL, out);
    }
    if (strcmp(args[0], "cat") == 0 && argc == 2) {
        return cmd_cat(session, args[1], out);
    }
    if (strcmp(args[0], "stat") == 0 && argc == 2) {
        return cmd_stat(session, args[1], out);
    }
    if ((strcmp(args[0], "cat") == 0 || strcmp(args[0], "stat") == 0) && argc == 1) {
        char buf[ARG_LEN + 32];
        snprintf(buf, sizeof buf, "%s: missing operand\n", args[0]);
        return out_text(out, SPOOKY_EXEC_ERR, buf);
    }

    {
        char buf[ARG_LEN + 32];
        snprintf(buf, sizeof buf, "%s: command not found\n", args[0]);
        return out_text(out, SPOOKY_EXEC_ERR, buf);
    }
}
