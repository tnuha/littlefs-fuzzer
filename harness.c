#include "lfs.h"

#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 4096
#define BLOCK_COUNT 128

static lfs_t lfs;
static uint8_t storage[BLOCK_SIZE * BLOCK_COUNT];
static uint32_t io_count;
static uint32_t fail_at;
static uint8_t fault_progress;
static jmp_buf power_cut;
static uint8_t read_cache[16];
static uint8_t prog_cache[16];
static uint8_t lookahead[16];

#define NO_FAULT UINT32_MAX

static int should_power_cut(void) {
  if (fail_at != NO_FAULT && io_count++ == fail_at) {
    fail_at = NO_FAULT;
    return 1;
  }

  return 0;
}

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
  if (should_power_cut()) {
    // A flash program may be interrupted after an arbitrary prefix was
    // programmed. Bits never transition from 0 back to 1.
    lfs_size_t partial = ((lfs_size_t)fault_progress * size) / UINT8_MAX;
    for (lfs_size_t i = 0; i < partial; ++i) {
      dst[i] &= src[i];
    }
    longjmp(power_cut, 1);
  }
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

  uint8_t *dst = storage + (size_t)block * cfg->block_size;
  if (should_power_cut()) {
    // Model a torn erase as a contiguous portion of the block reaching the
    // erased state before power is lost.
    lfs_size_t partial =
        ((lfs_size_t)fault_progress * cfg->block_size) / UINT8_MAX;
    memset(dst, 0xff, partial);
    longjmp(power_cut, 1);
  }
  memset(dst, 0xff, cfg->block_size);
  return 0;
}

static int user_provided_block_device_sync(const struct lfs_config *cfg) {
  (void)cfg;
  if (should_power_cut()) {
    longjmp(power_cut, 1);
  }
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

struct input {
  const uint8_t *data;
  size_t size;
  size_t pos;
};

static uint8_t next_byte(struct input *input) {
  return input->pos < input->size ? input->data[input->pos++] : 0;
}

static void close_files(lfs_file_t *files, uint8_t *open) {
  for (size_t i = 0; i < 4; ++i) {
    if (open[i]) {
      (void)lfs_file_close(&lfs, &files[i]);
      open[i] = 0;
    }
  }
}

static int mount_filesystem(void) {
  memset(&lfs, 0, sizeof(lfs));
  int err = lfs_mount(&lfs, &cfg);
  if (err) {
    // lfs_mount cleans up on failure but does not clear its freed pointers.
    memset(&lfs, 0, sizeof(lfs));
  }
  return err;
}

static int remount(lfs_file_t *files, uint8_t *open) {
  close_files(files, open);
  (void)lfs_unmount(&lfs);
  memset(files, 0, 4 * sizeof(*files));
  memset(open, 0, 4);
  return mount_filesystem();
}

static int count_blocks(void *data, lfs_block_t block) {
  (void)block;
  ++*(unsigned int *)data;
  return 0;
}

static int verify_mounted_filesystem(void) {
  struct lfs_fsinfo info;
  unsigned int blocks = 0;
  int err = lfs_fs_stat(&lfs, &info);
  if (err) {
    return err;
  }
  if (info.block_size != cfg.block_size || info.block_count != cfg.block_count) {
    return LFS_ERR_CORRUPT;
  }

  err = lfs_fs_traverse(&lfs, count_blocks, &blocks);
  if (err) {
    return err;
  }
  return blocks <= cfg.block_count ? 0 : LFS_ERR_CORRUPT;
}

static void require_recovery(const char *operation, int err) {
  if (err) {
    fprintf(stderr, "%s failed after power loss: %d\n", operation, err);
    abort();
  }
}

static int run_input(const uint8_t *data, size_t size) {
  static const char *const paths[] = {
      "alpha", "beta", "dir/a", "dir/b", "dir/sub/c", "log"};
  struct input input = {data, size, 0};
  lfs_file_t files[4] = {0};
  uint8_t file_buffers[4][16];
  struct lfs_file_config file_cfgs[4] = {
      {.buffer = file_buffers[0]}, {.buffer = file_buffers[1]},
      {.buffer = file_buffers[2]}, {.buffer = file_buffers[3]}};
  uint8_t open[4] = {0};
  uint8_t buffer[256];

  // Initialize valid media first. The fuzzer then chooses one I/O to fail.
  memset(storage, 0xff, sizeof(storage));
  memset(&lfs, 0, sizeof(lfs));
  fail_at = NO_FAULT;
  io_count = 0;
  if (lfs_format(&lfs, &cfg) || mount_filesystem()) {
    return 0;
  }

  int mounted = 1;
  // All littlefs buffers are caller-owned. Abandon the interrupted call
  // immediately, as real power loss would, without running its error cleanup.
  // Modified automatic variables are indeterminate after longjmp: reset the
  // handle arrays before using them, and do not resume the operation loop.
  if (setjmp(power_cut)) {
    memset(files, 0, sizeof(files));
    memset(open, 0, sizeof(open));
    memset(&lfs, 0, sizeof(lfs));
    require_recovery("mount", mount_filesystem());
    require_recovery("filesystem verification", verify_mounted_filesystem());
    require_recovery("unmount", lfs_unmount(&lfs));
    return 0;
  }
  fail_at = next_byte(&input) & 0x7f;
  fault_progress = next_byte(&input);
  size_t steps = 1 + (next_byte(&input) & 0x3f);
  for (size_t step = 0; step < steps; ++step) {
    unsigned int slot = next_byte(&input) & 3;
    unsigned int path = next_byte(&input) % (sizeof(paths) / sizeof(paths[0]));

    switch (next_byte(&input) % 19) {
    case 0:
      (void)lfs_mkdir(&lfs, "dir");
      break;
    case 1:
      (void)lfs_mkdir(&lfs, "dir/sub");
      break;
    case 2: {
      if (open[slot]) {
        (void)lfs_file_close(&lfs, &files[slot]);
      }
      int flags = LFS_O_RDWR | LFS_O_CREAT;
      uint8_t flag_bits = next_byte(&input);
      if (flag_bits & 1) {
        flags |= LFS_O_APPEND;
      }
      if (flag_bits & 2) {
        flags |= LFS_O_TRUNC;
      }
      if (flag_bits & 4) {
        flags |= LFS_O_EXCL;
      }
      open[slot] = lfs_file_opencfg(&lfs, &files[slot], paths[path],
                                    flags,
                                    &file_cfgs[slot]) == 0;
      break;
    }
    case 3:
      if (open[slot]) {
        size_t length = 1 + (next_byte(&input) % sizeof(buffer));
        for (size_t i = 0; i < length; ++i) {
          buffer[i] = next_byte(&input);
        }
        (void)lfs_file_write(&lfs, &files[slot], buffer, (lfs_size_t)length);
      }
      break;
    case 4:
      if (open[slot]) {
        (void)lfs_file_read(&lfs, &files[slot], buffer,
                            1 + (next_byte(&input) % sizeof(buffer)));
      }
      break;
    case 5:
      if (open[slot]) {
        (void)lfs_file_seek(&lfs, &files[slot], next_byte(&input),
                            next_byte(&input) % 3);
      }
      break;
    case 6:
      if (open[slot]) {
        (void)lfs_file_truncate(&lfs, &files[slot], next_byte(&input));
      }
      break;
    case 7:
      if (open[slot]) {
        (void)lfs_file_sync(&lfs, &files[slot]);
      }
      break;
    case 8:
      if (open[slot]) {
        (void)lfs_file_close(&lfs, &files[slot]);
        open[slot] = 0;
      }
      break;
    case 9:
      (void)lfs_rename(&lfs, paths[path],
                       paths[next_byte(&input) % (sizeof(paths) / sizeof(paths[0]))]);
      break;
    case 10:
      (void)lfs_remove(&lfs, paths[path]);
      break;
    case 11: {
      struct lfs_info info;
      (void)lfs_stat(&lfs, paths[path], &info);
      break;
    }
    case 12:
      buffer[0] = next_byte(&input);
      (void)lfs_setattr(&lfs, paths[path], next_byte(&input), buffer, 1);
      break;
    case 13:
      (void)lfs_getattr(&lfs, paths[path], next_byte(&input), buffer,
                        sizeof(buffer));
      break;
    case 14:
      (void)lfs_removeattr(&lfs, paths[path], next_byte(&input));
      break;
    case 15: {
      lfs_dir_t dir;
      struct lfs_info info;
      const char *directory = next_byte(&input) & 1 ? "/" : "dir";
      if (lfs_dir_open(&lfs, &dir, directory) == 0) {
        for (unsigned int i = 0; i < 8 && lfs_dir_read(&lfs, &dir, &info) > 0;
             ++i) {
        }
        lfs_soff_t position = lfs_dir_tell(&lfs, &dir);
        if (position >= 0) {
          (void)lfs_dir_seek(&lfs, &dir, (lfs_off_t)position);
        }
        (void)lfs_dir_rewind(&lfs, &dir);
        (void)lfs_dir_close(&lfs, &dir);
      }
      break;
    }
    case 16: {
      struct lfs_fsinfo info;
      unsigned int blocks = 0;
      (void)lfs_fs_stat(&lfs, &info);
      (void)lfs_fs_size(&lfs);
      (void)lfs_fs_traverse(&lfs, count_blocks, &blocks);
      (void)lfs_fs_mkconsistent(&lfs);
      (void)lfs_fs_gc(&lfs);
      break;
    }
    case 17:
      if (open[slot]) {
        (void)lfs_file_tell(&lfs, &files[slot]);
        (void)lfs_file_size(&lfs, &files[slot]);
        (void)lfs_file_rewind(&lfs, &files[slot]);
      }
      break;
    case 18:
      if (remount(files, open)) {
        require_recovery("normal remount", LFS_ERR_CORRUPT);
      }
      require_recovery("normal remount verification", verify_mounted_filesystem());
      break;
    default:
      break;
    }

    if (!mounted) {
      break;
    }
  }

  if (mounted) {
    close_files(files, open);
    (void)lfs_unmount(&lfs);
  }
  return 0;
}

int main(int argc, char **argv) {
  // One bounded testcase per process, read from AFL's @@ file or stdin.
  // 64 operations can consume at most 3 + 64 * 260 bytes.
  uint8_t data[3 + 64 * 260];
  if (argc > 2) {
    fprintf(stderr, "usage: %s [testcase]\n", argv[0]);
    return 2;
  }
  FILE *input = argc == 2 ? fopen(argv[1], "rb") : stdin;
  if (!input) {
    perror("open testcase");
    return 2;
  }
  size_t size = fread(data, 1, sizeof(data), input);
  int failed = ferror(input);
  if (input != stdin) {
    (void)fclose(input);
  }
  if (failed) {
    fprintf(stderr, "failed to read testcase\n");
    return 2;
  }
  return run_input(data, size);
}
