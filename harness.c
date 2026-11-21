#include "lfs.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 4096
#define BLOCK_COUNT 128

static lfs_t lfs;
static lfs_file_t file;
static uint8_t storage[BLOCK_SIZE * BLOCK_COUNT];
static uint8_t read_cache[16];
static uint8_t prog_cache[16];
static uint8_t lookahead[16];

static int user_provided_block_device_read(const struct lfs_config *cfg,
                                           lfs_block_t block, lfs_off_t off,
                                           void *buffer, lfs_size_t size) {
  if (block >= cfg->block_count || off > cfg->block_size ||
      size > cfg->block_size - off) {
    return LFS_ERR_IO;
  }

  memcpy(buffer, storage + (size_t)block * cfg->block_size + off, size);
  return 0;
}

static int user_provided_block_device_prog(const struct lfs_config *cfg,
                                           lfs_block_t block, lfs_off_t off,
                                           const void *buffer,
                                           lfs_size_t size) {
  if (block >= cfg->block_count || off > cfg->block_size ||
      size > cfg->block_size - off) {
    return LFS_ERR_IO;
  }

  // Emulate flash programming: bits can change from 1 to 0.
  uint8_t *dst = storage + (size_t)block * cfg->block_size + off;
  const uint8_t *src = buffer;
  for (lfs_size_t i = 0; i < size; ++i) {
    dst[i] &= src[i];
  }
  return 0;
}

static int user_provided_block_device_erase(const struct lfs_config *cfg,
                                            lfs_block_t block) {
  if (block >= cfg->block_count) {
    return LFS_ERR_IO;
  }

  memset(storage + (size_t)block * cfg->block_size, 0xff, cfg->block_size);
  return 0;
}

static int user_provided_block_device_sync(const struct lfs_config *cfg) {
  (void)cfg;
  return 0;
}

static const struct lfs_config cfg = {
    .read = user_provided_block_device_read,
    .prog = user_provided_block_device_prog,
    .erase = user_provided_block_device_erase,
    .sync = user_provided_block_device_sync,

    .read_size = 16,
    .prog_size = 16,
    .block_size = BLOCK_SIZE,
    .block_count = BLOCK_COUNT,
    .cache_size = 16,
    .lookahead_size = 16,
    .block_cycles = 500,

    .read_buffer = read_cache,
    .prog_buffer = prog_cache,
    .lookahead_buffer = lookahead,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Start with erased flash.
  memset(storage, 0xff, sizeof(storage));

  int err = lfs_mount(&lfs, &cfg);
  if (err) {
    err = lfs_format(&lfs, &cfg);
    if (err) {
      fprintf(stderr, "lfs_format failed: %d\n", err);
      return 0;
    }

    err = lfs_mount(&lfs, &cfg);
    if (err) {
      fprintf(stderr, "lfs_mount failed: %d\n", err);
      return 0;
    }
  }

  uint32_t boot_count = 0;

  err = lfs_file_open(&lfs, &file, "boot_count", LFS_O_RDWR | LFS_O_CREAT);
  if (err)
    goto fail;

  lfs_ssize_t n = lfs_file_read(&lfs, &file, &boot_count, sizeof(boot_count));
  if (n < 0) {
    err = (int)n;
    lfs_file_close(&lfs, &file);
    goto fail;
  }

  ++boot_count;

  err = lfs_file_rewind(&lfs, &file);
  if (err) {
    lfs_file_close(&lfs, &file);
    goto fail;
  }

  n = lfs_file_write(&lfs, &file, &boot_count, sizeof(boot_count));
  if (n != (lfs_ssize_t)sizeof(boot_count)) {
    err = n < 0 ? (int)n : LFS_ERR_IO;
    lfs_file_close(&lfs, &file);
    goto fail;
  }

  err = lfs_file_close(&lfs, &file);
  if (err)
    goto fail;

  err = lfs_file_open(&lfs, &file, data,
                      LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC);
  if (err)
    goto fail;

  n = lfs_file_write(&lfs, &file, data, (lfs_size_t)size);
  if (n != (lfs_ssize_t)size) {
    err = n < 0 ? (int)n : LFS_ERR_IO;
    lfs_file_close(&lfs, &file);
    goto fail;
  }

  err = lfs_file_close(&lfs, &file);
  if (err)
    goto fail;

  err = lfs_remove(&lfs, data);
  if (err)
    goto fail;

  err = lfs_rename(&lfs, data, "message.txt");
  if (err)
    goto fail;

  err = lfs_rename(&lfs, "message.txt", data);
  if (err)
    goto fail;

  struct lfs_info info;
  err = lfs_stat(&lfs, data, &info);
  if (err)
    goto fail;

  err = lfs_unmount(&lfs);
  if (err) {
    fprintf(stderr, "lfs_unmount failed: %d\n", err);
    return 1;
  }

  printf("boot_count: %" PRIu32 "\n", boot_count);
  printf("Wrote %zu bytes to message.txt in littlefs\n", size);
  return 0;

fail:
  fprintf(stderr, "littlefs operation failed: %d\n", err);
  lfs_unmount(&lfs);
  return 1;
}
