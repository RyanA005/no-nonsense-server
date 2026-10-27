#include "filesystem.h"
#include "network.h"
#include "users.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void usage(FILE *fp) {
    fputs("usage: spooky-server [--host ADDR] [--port PORT] [--data DIR] [--flag FLAG]\n", fp);
}

int main(int argc, char **argv) {
    const char *host = "0.0.0.0";
    const char *data = "data/runtime";
    const char *flag = NULL;
    int port = 19160;
    char err[256];
    size_t i;
    int opt;

    static struct option opts[] = {
        {"host", required_argument, NULL, 'H'},
        {"port", required_argument, NULL, 'p'},
        {"data", required_argument, NULL, 'd'},
        {"flag", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    while ((opt = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
        switch (opt) {
        case 'H':
            host = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            if (port < 0 || port > 65535) {
                fprintf(stderr, "invalid port\n");
                return 1;
            }
            break;
        case 'd':
            data = optarg;
            break;
        case 'f':
            flag = optarg;
            break;
        case 'h':
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 1;
        }
    }
    if (optind != argc) {
        usage(stderr);
        return 1;
    }
    if (flag == NULL) {
        const char *env = getenv("SPOOKY_FLAG");
        flag = (env != NULL && env[0] != '\0') ? env : "spooky{reused_k_no_nons3nse_89f3ae32316e}";
    }

    if (users_load(data, err, sizeof err) < 0) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }
    if (fs_load(data, flag, err, sizeof err) < 0) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }
    for (i = 0; i < users_count(); i++) {
        const struct spooky_user *user = users_at(i);
        const struct spooky_node *home = fs_lookup(user->home);
        if (home == NULL || !home->is_directory) {
            fprintf(stderr, "home directory missing for %s\n", user->name);
            return 1;
        }
    }

    fprintf(stderr, "spooky-server data=%s\n", data);
    if (spooky_server_run(host, port) < 0) {
        return 1;
    }
    return 0;
}
