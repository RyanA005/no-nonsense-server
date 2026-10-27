#ifndef SPOOKY_FILESYSTEM_H
#define SPOOKY_FILESYSTEM_H

#include <stddef.h>
#include <stdint.h>

#define SPOOKY_PATH_MAX 256
#define SPOOKY_MAX_OUTPUT (512 * 1024)

#define FS_OK 0
#define FS_NOT_FOUND 1
#define FS_DENIED 2
#define FS_NOT_DIR 3
#define FS_IS_DIR 4
#define FS_BAD_PATH 5

struct spooky_node {
    char path[SPOOKY_PATH_MAX];
    uint8_t *data;
    size_t size;
    uint32_t owner_uid;
    uint16_t mode;
    int is_directory;
};

int fs_load(const char *data_dir, const char *flag, char *err, size_t errlen);
const struct spooky_node *fs_lookup(const char *path);

int fs_visit(const char *cwd, const char *input, uint32_t uid, int require,
             char *out_path, size_t out_sz, const struct spooky_node **node_out);

int fs_list(const char *dir, uint8_t **data_out, size_t *len_out);

#endif
