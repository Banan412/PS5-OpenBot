/*
 * ps5_sqlite_shim.h
 *
 * CRITICAL ABI SHIM FOR PS5 PAYLOADS (FreeBSD 11 kernel vs FreeBSD 12 Rust std)
 *
 * ps5-payload-dev/sdk's <sys/stat.h> defines struct stat with the FreeBSD 11
 * 120-byte layout. Meanwhile, ps5-rt exports stat/fstat/lstat taking
 * Rust's FreeBSD 12 224-byte Stat12 layout.
 *
 * Including this header when compiling C libraries (such as sqlite3.c)
 * redirects C stat/fstat/lstat calls to ps5-rt's 120-byte FreeBSD 11
 * wrappers (__ps5_stat11, __ps5_fstat11, __ps5_lstat11), preventing stack
 * corruption and misread st_size fields.
 */
#ifndef PS5_SQLITE_SHIM_H
#define PS5_SQLITE_SHIM_H

#ifndef __ASSEMBLER__
#include <sys/stat.h>

int stat(const char *path, struct stat *sb) __asm__("__ps5_stat11");
int fstat(int fd, struct stat *sb) __asm__("__ps5_fstat11");
int lstat(const char *path, struct stat *sb) __asm__("__ps5_lstat11");
#endif

#endif /* PS5_SQLITE_SHIM_H */
