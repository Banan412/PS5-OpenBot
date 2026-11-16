//! PS5 FW 13.40 (FreeBSD 11) runtime compatibility crate for Rust `std`.
//!
//! Enabled when `target_vendor = "sie"`; empty on host targets.
#![no_std]
#![cfg_attr(not(target_vendor = "sie"), allow(unused))]

#[cfg(target_vendor = "sie")]
mod rt_impl {
    use core::ffi::{c_char, c_int, c_void};

    // FreeBSD 11 syscall numbers (verified against ps5-payload-sdk sys/syscall.h).
    const SYS_READ: u64 = 3;
    const SYS_OPEN: u64 = 5;
    const SYS_CLOSE: u64 = 6;
    const SYS_GETUID: u64 = 24;
    const SYS_GETEUID: u64 = 25;
    const SYS_RECVMSG: u64 = 27;
    const SYS_RECVFROM: u64 = 29;
    const SYS_GETPID: u64 = 20;
    const SYS_KILL: u64 = 37;
    const SYS_ACCEPT: u64 = 30;
    const SYS_ACCESS: u64 = 33;
    const SYS_GETEGID: u64 = 43;
    const SYS_GETGID: u64 = 47;
    const SYS_READLINK: u64 = 58;
    const SYS_DUP2: u64 = 90;
    const SYS_FCNTL: u64 = 92;
    const SYS_GETSOCKOPT: u64 = 118;
    const SYS_STAT11: u64 = 188;
    const SYS_FSTAT11: u64 = 189;
    const SYS_LSTAT11: u64 = 190;
    const SYS_GETDIRENTRIES: u64 = 196;
    const SYS___SYSCTL: u64 = 202;
    const SYS_CLOCK_GETTIME: u64 = 232;
    const SYS_NANOSLEEP: u64 = 240;
    const SYS_CLOCK_NANOSLEEP: u64 = 244;
    const SYS_KQUEUE: u64 = 362;
    const SYS_KEVENT: u64 = 363;
    const SYS_EACCESS: u64 = 376;
    const SYS_THR_SET_NAME: u64 = 464;
    const SYS_FSTATAT11: u64 = 493;

    // Errno constants (ps5-payload-sdk sys/errno.h).
    const EINTR: c_int = 4;
    const EIO: c_int = 5;
    const EBADF: c_int = 9;
    const ENOMEM: c_int = 12;
    const EFAULT: c_int = 14;
    const ENOTDIR: c_int = 20;
    const EINVAL: c_int = 22;
    const EAGAIN: c_int = 35;
    const ENOSYS: c_int = 78;

    // fcntl / open / socket / kqueue constants.
    const F_DUPFD: c_int = 0;
    const F_SETFD: c_int = 2;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    const F_DUPFD_CLOEXEC: c_int = 17;
    const FD_CLOEXEC: c_int = 1;

    const O_RDONLY: c_int = 0;
    const O_RDWR: c_int = 2;
    const O_NONBLOCK: c_int = 0x4;
    const O_DIRECTORY: c_int = 0x0002_0000;
    const O_CLOEXEC: c_int = 0x0010_0000;

    const SOCK_CLOEXEC: c_int = 0x1000_0000;
    const SOCK_NONBLOCK: c_int = 0x2000_0000;
    const SOL_SOCKET: c_int = 0xffff;
    const SO_RCVTIMEO: c_int = 0x1006;
    const MSG_DONTWAIT: c_int = 0x80;

    const EVFILT_READ: i16 = -1;
    const EV_ADD: u16 = 0x1;
    const EV_ONESHOT: u16 = 0x10;

    const AT_FDCWD: c_int = -100;
    const AT_EACCESS: c_int = 0x100;
    const TIMER_ABSTIME: c_int = 1;

    const CTL_KERN: i32 = 1;
    const KERN_PROC: i32 = 14;
    const KERN_PROC_PID: i32 = 1;
    const KERN_PROC_ARGS: i32 = 7;
    const KERN_BOOTTIME: i32 = 21;
    const KERN_ARND: i32 = 37;
    const SIGHUP: c_int = 1;
    const SIGPIPE: c_int = 13;
    const SIG_IGN: usize = 1;

    const S_IFMT: u16 = 0o170000;
    const S_IFDIR: u16 = 0o040000;

    const DIRBUF_MIN: usize = 8192;
    const DIRBUF_MAX: usize = 1 << 20;

    extern "C" {
        fn __error() -> *mut c_int;
        fn malloc(n: usize) -> *mut c_void;
        fn free(p: *mut c_void);
        fn realloc(p: *mut c_void, n: usize) -> *mut c_void;
        fn pthread_self() -> usize;
        fn signal(sig: c_int, handler: usize) -> usize;
        fn qsort(
            base: *mut c_void,
            n: usize,
            size: usize,
            cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
        );
        fn strcoll(a: *const c_char, b: *const c_char) -> c_int;
    }

    /// Raw FreeBSD x86-64 syscall: carry flag indicates error with errno in rax.
    #[inline]
    unsafe fn syscall6(n: u64, a: [u64; 6]) -> i64 {
        let ret: i64;
        let failed: u8;
        core::arch::asm!(
            "syscall",
            "setc {failed}",
            failed = out(reg_byte) failed,
            inlateout("rax") n as i64 => ret,
            in("rdi") a[0],
            in("rsi") a[1],
            in("rdx") a[2],
            in("r10") a[3],
            in("r8") a[4],
            in("r9") a[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
        if failed != 0 {
            *__error() = ret as c_int;
            -1
        } else {
            ret
        }
    }

    #[inline]
    unsafe fn sys_close(fd: c_int) -> c_int {
        syscall6(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0]) as c_int
    }

    unsafe fn close_preserving_errno(fd: c_int) {
        let errno = *__error();
        sys_close(fd);
        *__error() = errno;
    }

    #[inline]
    unsafe fn sys_fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
        syscall6(SYS_FCNTL, [fd as u64, cmd as u64, arg as u64, 0, 0, 0]) as c_int
    }

    // -----------------------------------------------------------------------
    // Fail-closed getrandom (FreeBSD 12+):
    // 1. Try SYS___sysctl([CTL_KERN=1, KERN_ARND=37]) in <= 256-byte chunks.
    // 2. If incomplete, open /dev/urandom (O_RDONLY | O_CLOEXEC) and read,
    //    retrying only EINTR.
    // 3. Never fall back to arc4random_buf, gettimeofday, or getpid. If fewer
    //    than `len` bytes are read, wipe output, preserve/set errno (EIO if 0),
    //    and return -1.

    #[no_mangle]
    pub unsafe extern "C" fn getrandom(buf: *mut c_void, len: usize, _flags: u32) -> isize {
        if len == 0 {
            return 0;
        }
        if buf.is_null() {
            *__error() = EFAULT;
            return -1;
        }
        if len > isize::MAX as usize {
            *__error() = EINVAL;
            return -1;
        }

        let out = buf as *mut u8;
        let mib: [i32; 2] = [CTL_KERN, KERN_ARND];
        let mut offset: usize = 0;
        let mut last_errno: c_int = 0;

        while offset < len {
            let want = (len - offset).min(256);
            let mut got = want;
            let ret = syscall6(
                SYS___SYSCTL,
                [
                    mib.as_ptr() as u64,
                    2,
                    out.add(offset) as u64,
                    &mut got as *mut usize as u64,
                    0,
                    0,
                ],
            );
            if ret < 0 {
                let e = *__error();
                if e == EINTR {
                    continue;
                }
                if e != 0 {
                    last_errno = e;
                }
                break;
            }
            if got == 0 {
                break;
            }
            offset += got.min(want);
        }

        if offset < len {
            let fd = loop {
                let r = syscall6(
                    SYS_OPEN,
                    [
                        b"/dev/urandom\0".as_ptr() as u64,
                        (O_RDONLY | O_CLOEXEC) as u64,
                        0,
                        0,
                        0,
                        0,
                    ],
                );
                if r < 0 && *__error() == EINTR {
                    continue;
                }
                break r as c_int;
            };
            if fd < 0 {
                let e = *__error();
                if e != 0 {
                    last_errno = e;
                }
            } else {
                while offset < len {
                    let n = syscall6(
                        SYS_READ,
                        [
                            fd as u64,
                            out.add(offset) as u64,
                            (len - offset) as u64,
                            0,
                            0,
                            0,
                        ],
                    );
                    if n < 0 {
                        let e = *__error();
                        if e == EINTR {
                            continue;
                        }
                        if e != 0 {
                            last_errno = e;
                        }
                        break;
                    }
                    if n == 0 {
                        break;
                    }
                    offset += (n as usize).min(len - offset);
                }
                sys_close(fd);
            }
        }

        if offset < len {
            for i in 0..len {
                core::ptr::write_volatile(out.add(i), 0);
            }
            *__error() = if last_errno != 0 { last_errno } else { EIO };
            return -1;
        }

        len as isize
    }

    // -----------------------------------------------------------------------
    // Misc POSIX/BSD symbols missing from PS5 SDK.

    #[no_mangle]
    pub unsafe extern "C" fn accept4(
        fd: c_int,
        addr: *mut c_void,
        len: *mut u32,
        flags: c_int,
    ) -> c_int {
        let s = accept(fd, addr, len);
        if s < 0 {
            return s;
        }
        if flags & SOCK_CLOEXEC != 0 && sys_fcntl(s, F_SETFD, FD_CLOEXEC as usize) < 0 {
            close_preserving_errno(s);
            return -1;
        }
        if flags & SOCK_NONBLOCK != 0 {
            let fl = sys_fcntl(s, F_GETFL, 0);
            if fl < 0 || sys_fcntl(s, F_SETFL, (fl | O_NONBLOCK) as usize) < 0 {
                close_preserving_errno(s);
                return -1;
            }
        }
        s
    }

    /// Thread names are cosmetic; keeping this a no-op preserves the payload
    /// process name (`ps5-openbot.elf`) in `pldmgr` instead of `tokio-rt-worker`.
    #[no_mangle]
    pub extern "C" fn pthread_setname_np(_thread: usize, _name: *const c_char) -> c_int {
        0
    }

    #[no_mangle]
    pub extern "C" fn dl_iterate_phdr(_cb: *const c_void, _data: *mut c_void) -> c_int {
        0
    }

    // -----------------------------------------------------------------------
    // kevent: FreeBSD 12 (64B) <-> FreeBSD 11 (32B).

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Kevent12 {
        pub ident: usize,
        pub filter: i16,
        pub flags: u16,
        pub fflags: u32,
        pub data: i64,
        pub udata: *mut c_void,
        pub ext: [u64; 4],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Kevent11 {
        ident: usize,
        filter: i16,
        flags: u16,
        fflags: u32,
        data: i64,
        udata: *mut c_void,
    }

    const _: () = assert!(core::mem::size_of::<Kevent11>() == 32);
    const _: () = assert!(core::mem::size_of::<Kevent12>() == 64);

    #[no_mangle]
    pub unsafe extern "C" fn kevent(
        kq: c_int,
        changes: *const Kevent12,
        nchanges: c_int,
        events: *mut Kevent12,
        nevents: c_int,
        timeout: *const c_void,
    ) -> c_int {
        const STACK_CAP_C: usize = 64;
        const STACK_CAP_E: usize = 128;
        let nc = nchanges.max(0) as usize;
        let ne = nevents.max(0) as usize;
        let size = core::mem::size_of::<Kevent11>();
        let zero = Kevent11 {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: core::ptr::null_mut(),
        };
        let mut stack_changes = [zero; STACK_CAP_C];
        let mut stack_events = [zero; STACK_CAP_E];

        let mut heap_changes: *mut Kevent11 = core::ptr::null_mut();
        let mut heap_events: *mut Kevent11 = core::ptr::null_mut();
        let old_changes = if nc == 0 {
            core::ptr::null_mut()
        } else if nc <= STACK_CAP_C {
            stack_changes.as_mut_ptr()
        } else {
            heap_changes = malloc(nc * size) as *mut Kevent11;
            heap_changes
        };
        let old_events = if ne == 0 {
            core::ptr::null_mut()
        } else if ne <= STACK_CAP_E {
            stack_events.as_mut_ptr()
        } else {
            heap_events = malloc(ne * size) as *mut Kevent11;
            heap_events
        };
        if (nc > 0 && old_changes.is_null()) || (ne > 0 && old_events.is_null()) {
            free(heap_changes.cast());
            free(heap_events.cast());
            *__error() = ENOMEM;
            return -1;
        }

        for i in 0..nc {
            let c = &*changes.add(i);
            *old_changes.add(i) = Kevent11 {
                ident: c.ident,
                filter: c.filter,
                flags: c.flags,
                fflags: c.fflags,
                data: c.data,
                udata: c.udata,
            };
        }

        let ret = syscall6(
            SYS_KEVENT,
            [
                kq as u64,
                old_changes as u64,
                nc as u64,
                old_events as u64,
                ne as u64,
                timeout as u64,
            ],
        );

        if ret > 0 {
            for i in 0..(ret as usize).min(ne) {
                let e = *old_events.add(i);
                *events.add(i) = Kevent12 {
                    ident: e.ident,
                    filter: e.filter,
                    flags: e.flags,
                    fflags: e.fflags,
                    data: e.data,
                    udata: e.udata,
                    ext: [0; 4],
                };
            }
        }
        free(heap_changes.cast());
        free(heap_events.cast());
        ret as c_int
    }

    // -----------------------------------------------------------------------
    // fcntl: emulate F_DUPFD_CLOEXEC.

    #[no_mangle]
    pub unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
        if cmd != F_DUPFD_CLOEXEC {
            return sys_fcntl(fd, cmd, arg);
        }
        let new = sys_fcntl(fd, F_DUPFD, arg);
        if new >= 0 && sys_fcntl(new, F_SETFD, FD_CLOEXEC as usize) < 0 {
            close_preserving_errno(new);
            return -1;
        }
        new
    }

    // -----------------------------------------------------------------------
    // stat family: FreeBSD 11 (120B) <-> FreeBSD 12 (224B).

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Timespec {
        sec: i64,
        nsec: i64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Stat11 {
        dev: u32,
        ino: u32,
        mode: u16,
        nlink: u16,
        uid: u32,
        gid: u32,
        rdev: u32,
        atim: Timespec,
        mtim: Timespec,
        ctim: Timespec,
        size: i64,
        blocks: i64,
        blksize: i32,
        flags: u32,
        gen: u32,
        lspare: i32,
        birthtim: Timespec,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Stat12 {
        pub dev: u64,
        pub ino: u64,
        pub nlink: u64,
        pub mode: u16,
        pad0: i16,
        pub uid: u32,
        pub gid: u32,
        pad1: i32,
        pub rdev: u64,
        pub atime: i64,
        pub atime_nsec: i64,
        pub mtime: i64,
        pub mtime_nsec: i64,
        pub ctime: i64,
        pub ctime_nsec: i64,
        pub birthtime: i64,
        pub birthtime_nsec: i64,
        pub size: i64,
        pub blocks: i64,
        pub blksize: i32,
        pub flags: u32,
        pub gen: u64,
        spare: [u64; 10],
    }

    const _: () = assert!(core::mem::size_of::<Stat11>() == 120);
    const _: () = assert!(core::mem::size_of::<Stat12>() == 224);

    unsafe fn widen_stat(old: &Stat11, out: *mut Stat12) {
        *out = Stat12 {
            dev: old.dev as u64,
            ino: old.ino as u64,
            nlink: old.nlink as u64,
            mode: old.mode,
            pad0: 0,
            uid: old.uid,
            gid: old.gid,
            pad1: 0,
            rdev: old.rdev as u64,
            atime: old.atim.sec,
            atime_nsec: old.atim.nsec,
            mtime: old.mtim.sec,
            mtime_nsec: old.mtim.nsec,
            ctime: old.ctim.sec,
            ctime_nsec: old.ctim.nsec,
            birthtime: old.birthtim.sec,
            birthtime_nsec: old.birthtim.nsec,
            size: old.size,
            blocks: old.blocks,
            blksize: old.blksize,
            flags: old.flags,
            gen: old.gen as u64,
            spare: [0; 10],
        };
    }

    unsafe fn stat_call(n: u64, args: [u64; 6], buf_arg: usize, out: *mut Stat12) -> c_int {
        if out.is_null() {
            *__error() = EFAULT;
            return -1;
        }
        let mut old: Stat11 = core::mem::zeroed();
        let mut a = args;
        a[buf_arg] = &mut old as *mut Stat11 as u64;
        let ret = syscall6(n, a);
        if ret == 0 {
            widen_stat(&old, out);
        }
        ret as c_int
    }

    #[no_mangle]
    pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut Stat12) -> c_int {
        stat_call(SYS_STAT11, [path as u64, 0, 0, 0, 0, 0], 1, buf)
    }

    #[no_mangle]
    pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut Stat12) -> c_int {
        stat_call(SYS_LSTAT11, [path as u64, 0, 0, 0, 0, 0], 1, buf)
    }

    #[no_mangle]
    pub unsafe extern "C" fn fstat(fd: c_int, buf: *mut Stat12) -> c_int {
        stat_call(SYS_FSTAT11, [fd as u64, 0, 0, 0, 0, 0], 1, buf)
    }

    #[no_mangle]
    pub unsafe extern "C" fn fstatat(
        fd: c_int,
        path: *const c_char,
        buf: *mut Stat12,
        flag: c_int,
    ) -> c_int {
        stat_call(SYS_FSTATAT11, [fd as u64, path as u64, 0, flag as u64, 0, 0], 2, buf)
    }

    #[no_mangle]
    pub unsafe extern "C" fn __ps5_stat11(path: *const c_char, buf: *mut c_void) -> c_int {
        syscall6(SYS_STAT11, [path as u64, buf as u64, 0, 0, 0, 0]) as c_int
    }

    #[no_mangle]
    pub unsafe extern "C" fn __ps5_fstat11(fd: c_int, buf: *mut c_void) -> c_int {
        syscall6(SYS_FSTAT11, [fd as u64, buf as u64, 0, 0, 0, 0]) as c_int
    }

    #[no_mangle]
    pub unsafe extern "C" fn __ps5_lstat11(path: *const c_char, buf: *mut c_void) -> c_int {
        syscall6(SYS_LSTAT11, [path as u64, buf as u64, 0, 0, 0, 0]) as c_int
    }

    // -----------------------------------------------------------------------
    // Directory API over SYS_getdirentries (FreeBSD 11 -> FreeBSD 12 dirent).

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Dirent12 {
        pub fileno: u64,
        pub off: i64,
        pub reclen: u16,
        pub kind: u8,
        pad0: u8,
        pub namlen: u16,
        pad1: u16,
        pub name: [c_char; 256],
    }

    #[repr(C)]
    struct Dirent11Head {
        fileno: u32,
        reclen: u16,
        kind: u8,
        namlen: u8,
    }

    pub struct Dir {
        fd: c_int,
        buf: *mut u8,
        cap: usize,
        len: usize,
        pos: usize,
        base: i64,
        ent: Dirent12,
    }

    #[no_mangle]
    pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut Dir {
        let mut st: Stat11 = core::mem::zeroed();
        if syscall6(
            SYS_FSTAT11,
            [fd as u64, &mut st as *mut Stat11 as u64, 0, 0, 0, 0],
        ) != 0
        {
            return core::ptr::null_mut();
        }
        if (st.mode & S_IFMT) != S_IFDIR {
            *__error() = ENOTDIR;
            return core::ptr::null_mut();
        }
        let cap = (st.blksize.max(0) as usize).clamp(DIRBUF_MIN, DIRBUF_MAX);

        let d = malloc(core::mem::size_of::<Dir>()) as *mut Dir;
        let buf = malloc(cap) as *mut u8;
        if d.is_null() || buf.is_null() {
            free(d.cast());
            free(buf.cast());
            *__error() = ENOMEM;
            return core::ptr::null_mut();
        }
        (*d).fd = fd;
        (*d).buf = buf;
        (*d).cap = cap;
        (*d).len = 0;
        (*d).pos = 0;
        (*d).base = 0;
        sys_fcntl(fd, F_SETFD, FD_CLOEXEC as usize);
        d
    }

    #[no_mangle]
    pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut Dir {
        let fd = syscall6(
            SYS_OPEN,
            [
                path as u64,
                (O_RDONLY | O_DIRECTORY | O_CLOEXEC) as u64,
                0,
                0,
                0,
                0,
            ],
        ) as c_int;
        if fd < 0 {
            return core::ptr::null_mut();
        }
        let d = fdopendir(fd);
        if d.is_null() {
            close_preserving_errno(fd);
        }
        d
    }

    #[no_mangle]
    pub unsafe extern "C" fn readdir(d: *mut Dir) -> *mut Dirent12 {
        if d.is_null() {
            *__error() = EBADF;
            return core::ptr::null_mut();
        }
        let d = &mut *d;
        loop {
            if d.pos >= d.len {
                let n = syscall6(
                    SYS_GETDIRENTRIES,
                    [
                        d.fd as u64,
                        d.buf as u64,
                        d.cap as u64,
                        &mut d.base as *mut i64 as u64,
                        0,
                        0,
                    ],
                ) as isize;
                if n <= 0 {
                    return core::ptr::null_mut();
                }
                d.len = (n as usize).min(d.cap);
                d.pos = 0;
            }
            let hsize = core::mem::size_of::<Dirent11Head>();
            if d.pos + hsize > d.len {
                d.pos = d.len;
                continue;
            }
            let head = &*(d.buf.add(d.pos) as *const Dirent11Head);
            let reclen = head.reclen as usize;
            if reclen < hsize || d.pos + reclen > d.len {
                d.pos = d.len;
                continue;
            }
            let name = d.buf.add(d.pos + hsize);
            d.pos += reclen;
            if head.fileno == 0 {
                continue;
            }
            let n = (head.namlen as usize).min(255).min(reclen - hsize);
            d.ent.fileno = head.fileno as u64;
            d.ent.off = 0;
            d.ent.reclen = core::mem::size_of::<Dirent12>() as u16;
            d.ent.kind = head.kind;
            d.ent.namlen = n as u16;
            core::ptr::copy_nonoverlapping(name, d.ent.name.as_mut_ptr().cast(), n);
            d.ent.name[n] = 0;
            return &mut d.ent;
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn closedir(d: *mut Dir) -> c_int {
        if d.is_null() {
            *__error() = EBADF;
            return -1;
        }
        let r = sys_close((*d).fd);
        free((*d).buf.cast());
        free(d.cast());
        r
    }

    #[no_mangle]
    pub unsafe extern "C" fn dirfd(d: *mut Dir) -> c_int {
        if d.is_null() {
            *__error() = EBADF;
            return -1;
        }
        (*d).fd
    }

    type DirentCmp = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

    #[no_mangle]
    pub unsafe extern "C" fn scandir(
        path: *const c_char,
        namelist: *mut *mut *mut Dirent12,
        select: Option<unsafe extern "C" fn(*const Dirent12) -> c_int>,
        compar: Option<DirentCmp>,
    ) -> c_int {
        let d = opendir(path);
        if d.is_null() {
            return -1;
        }
        let mut list: *mut *mut Dirent12 = core::ptr::null_mut();
        let mut len = 0usize;
        let mut cap = 0usize;
        let fail = |list: *mut *mut Dirent12, len: usize, d: *mut Dir| {
            for i in 0..len {
                free((*list.add(i)).cast());
            }
            free(list.cast());
            closedir(d);
            *__error() = ENOMEM;
            -1
        };
        loop {
            let e = readdir(d);
            if e.is_null() {
                break;
            }
            if let Some(sel) = select {
                if sel(e) == 0 {
                    continue;
                }
            }
            if len == cap {
                cap = if cap == 0 { 32 } else { cap * 2 };
                let grown = realloc(
                    list.cast(),
                    cap * core::mem::size_of::<*mut Dirent12>(),
                ) as *mut *mut Dirent12;
                if grown.is_null() {
                    return fail(list, len, d);
                }
                list = grown;
            }
            let copy = malloc(core::mem::size_of::<Dirent12>()) as *mut Dirent12;
            if copy.is_null() {
                return fail(list, len, d);
            }
            *copy = *e;
            *list.add(len) = copy;
            len += 1;
        }
        closedir(d);
        if let (Some(cmp), true) = (compar, len > 1) {
            qsort(
                list.cast(),
                len,
                core::mem::size_of::<*mut Dirent12>(),
                cmp,
            );
        }
        *namelist = list;
        len as c_int
    }

    #[no_mangle]
    pub unsafe extern "C" fn alphasort(a: *const c_void, b: *const c_void) -> c_int {
        let a = *(a as *const *const Dirent12);
        let b = *(b as *const *const Dirent12);
        strcoll((*a).name.as_ptr(), (*b).name.as_ptr())
    }

    // -----------------------------------------------------------------------
    // faccessat / readlinkat over access / readlink when AT_FDCWD or absolute.

    unsafe fn at_cwd_or_absolute(fd: c_int, path: *const c_char) -> bool {
        fd == AT_FDCWD || (!path.is_null() && *path == b'/' as c_char)
    }

    #[no_mangle]
    pub unsafe extern "C" fn faccessat(
        fd: c_int,
        path: *const c_char,
        mode: c_int,
        flag: c_int,
    ) -> c_int {
        if !at_cwd_or_absolute(fd, path) || flag & !AT_EACCESS != 0 {
            *__error() = ENOSYS;
            return -1;
        }
        if flag & AT_EACCESS == 0 {
            return syscall6(SYS_ACCESS, [path as u64, mode as u64, 0, 0, 0, 0]) as c_int;
        }
        let ret = syscall6(SYS_EACCESS, [path as u64, mode as u64, 0, 0, 0, 0]) as c_int;
        if ret == 0 || *__error() != ENOSYS {
            return ret;
        }
        let ids = |n| syscall6(n, [0; 6]);
        if ids(SYS_GETUID) == ids(SYS_GETEUID) && ids(SYS_GETGID) == ids(SYS_GETEGID) {
            return syscall6(SYS_ACCESS, [path as u64, mode as u64, 0, 0, 0, 0]) as c_int;
        }
        *__error() = ENOSYS;
        -1
    }

    #[no_mangle]
    pub unsafe extern "C" fn readlinkat(
        fd: c_int,
        path: *const c_char,
        buf: *mut c_char,
        size: usize,
    ) -> isize {
        if !at_cwd_or_absolute(fd, path) {
            *__error() = ENOSYS;
            return -1;
        }
        syscall6(SYS_READLINK, [path as u64, buf as u64, size as u64, 0, 0, 0]) as isize
    }

    // -----------------------------------------------------------------------
    // clock_nanosleep with nanosleep fallback on ENOSYS.

    #[no_mangle]
    pub unsafe extern "C" fn clock_nanosleep(
        clock: c_int,
        flags: c_int,
        rq: *const Timespec,
        rm: *mut Timespec,
    ) -> c_int {
        let saved = *__error();
        let ret = syscall6(
            SYS_CLOCK_NANOSLEEP,
            [clock as u64, flags as u64, rq as u64, rm as u64, 0, 0],
        );
        let err = *__error();
        *__error() = saved;
        if ret == 0 {
            return 0;
        }
        if err != ENOSYS {
            return err;
        }
        if rq.is_null() {
            return EINVAL;
        }
        let mut req = *rq;
        if flags & TIMER_ABSTIME != 0 {
            let mut now = Timespec { sec: 0, nsec: 0 };
            if syscall6(
                SYS_CLOCK_GETTIME,
                [clock as u64, &mut now as *mut _ as u64, 0, 0, 0, 0],
            ) != 0
            {
                let e = *__error();
                *__error() = saved;
                return e;
            }
            req.sec -= now.sec;
            req.nsec -= now.nsec;
            if req.nsec < 0 {
                req.nsec += 1_000_000_000;
                req.sec -= 1;
            }
            if req.sec < 0 {
                return 0;
            }
        }
        let rm = if flags & TIMER_ABSTIME != 0 {
            core::ptr::null_mut()
        } else {
            rm
        };
        let ret = syscall6(
            SYS_NANOSLEEP,
            [&req as *const _ as u64, rm as u64, 0, 0, 0, 0],
        );
        let err = *__error();
        *__error() = saved;
        if ret == 0 { 0 } else { err }
    }

    // -----------------------------------------------------------------------
    // Rest-mode-safe blocking accept / recv / recvfrom / recvmsg via kqueue/kevent.

    #[repr(C)]
    struct Timeval {
        sec: i64,
        usec: i64,
    }

    unsafe fn kevent_wait(fd: c_int, timeout: *const Timespec) -> c_int {
        let saved = *__error();
        let kq = syscall6(SYS_KQUEUE, [0; 6]);
        if kq < 0 {
            *__error() = saved;
            return 0;
        }
        let ch = Kevent11 {
            ident: fd as usize,
            filter: EVFILT_READ,
            flags: EV_ADD | EV_ONESHOT,
            fflags: 0,
            data: 0,
            udata: core::ptr::null_mut(),
        };
        let mut ev = ch;
        let r = syscall6(
            SYS_KEVENT,
            [
                kq as u64,
                &ch as *const _ as u64,
                1,
                &mut ev as *mut _ as u64,
                1,
                timeout as u64,
            ],
        );
        let err = *__error();
        sys_close(kq as c_int);
        if r < 0 && err == EINTR {
            *__error() = EINTR;
            return -1;
        }
        if r == 0 && !timeout.is_null() {
            *__error() = EAGAIN;
            return -1;
        }
        *__error() = saved;
        0
    }

    unsafe fn wait_readable(fd: c_int) -> c_int {
        let fl = sys_fcntl(fd, F_GETFL, 0);
        if fl < 0 || fl & O_NONBLOCK != 0 {
            return 0;
        }
        kevent_wait(fd, core::ptr::null())
    }

    unsafe fn wait_socket_readable(fd: c_int, flags: c_int) -> c_int {
        if flags & MSG_DONTWAIT != 0 {
            return 0;
        }
        let fl = sys_fcntl(fd, F_GETFL, 0);
        if fl < 0 || fl & O_NONBLOCK != 0 {
            return 0;
        }
        let saved = *__error();
        let mut tv = Timeval { sec: 0, usec: 0 };
        let mut len = core::mem::size_of::<Timeval>() as u32;
        let r = syscall6(
            SYS_GETSOCKOPT,
            [
                fd as u64,
                SOL_SOCKET as u64,
                SO_RCVTIMEO as u64,
                &mut tv as *mut _ as u64,
                &mut len as *mut _ as u64,
                0,
            ],
        );
        *__error() = saved;
        if r < 0 {
            return 0;
        }
        let ts = Timespec {
            sec: tv.sec,
            nsec: tv.usec * 1000,
        };
        let timeout = if tv.sec == 0 && tv.usec == 0 {
            core::ptr::null()
        } else {
            &ts as *const Timespec
        };
        kevent_wait(fd, timeout)
    }

    #[no_mangle]
    pub unsafe extern "C" fn accept(
        fd: c_int,
        addr: *mut c_void,
        len: *mut u32,
    ) -> c_int {
        if wait_readable(fd) < 0 {
            return -1;
        }
        syscall6(SYS_ACCEPT, [fd as u64, addr as u64, len as u64, 0, 0, 0]) as c_int
    }

    #[no_mangle]
    pub unsafe extern "C" fn recvfrom(
        fd: c_int,
        buf: *mut c_void,
        len: usize,
        flags: c_int,
        from: *mut c_void,
        fromlen: *mut u32,
    ) -> isize {
        if wait_socket_readable(fd, flags) < 0 {
            return -1;
        }
        syscall6(
            SYS_RECVFROM,
            [
                fd as u64,
                buf as u64,
                len as u64,
                flags as u64,
                from as u64,
                fromlen as u64,
            ],
        ) as isize
    }

    #[no_mangle]
    pub unsafe extern "C" fn recv(
        fd: c_int,
        buf: *mut c_void,
        len: usize,
        flags: c_int,
    ) -> isize {
        recvfrom(fd, buf, len, flags, core::ptr::null_mut(), core::ptr::null_mut())
    }

    #[no_mangle]
    pub unsafe extern "C" fn recvmsg(
        fd: c_int,
        msg: *mut c_void,
        flags: c_int,
    ) -> isize {
        if wait_socket_readable(fd, flags) < 0 {
            return -1;
        }
        syscall6(SYS_RECVMSG, [fd as u64, msg as u64, flags as u64, 0, 0, 0]) as isize
    }

    // -----------------------------------------------------------------------
    // Process naming (pldmgr), signals, boot time, and PID inspection.

    pub const SIGTERM: c_int = 15;
    pub const SIGKILL: c_int = 9;

    pub fn ignore_daemon_signals() {
        unsafe {
            signal(SIGPIPE, SIG_IGN);
            signal(SIGHUP, SIG_IGN);
        }
    }

    pub fn current_pid() -> i32 {
        unsafe { syscall6(SYS_GETPID, [0; 6]) as i32 }
    }

    pub fn is_pid_alive(pid: i32) -> bool {
        if pid <= 1 {
            return false;
        }
        unsafe { syscall6(SYS_KILL, [pid as u64, 0, 0, 0, 0, 0]) == 0 }
    }

    pub fn kill_pid(pid: i32, sig: c_int) -> c_int {
        if pid <= 1 {
            return -1;
        }
        unsafe { syscall6(SYS_KILL, [pid as u64, sig as u64, 0, 0, 0, 0]) as c_int }
    }

    /// Sets both FreeBSD kernel thread/process name (`SYS_thr_set_name`) and
    /// `KERN_PROC_ARGS` proctitle so `pldmgr` does not show `payload.elf`.
    pub fn set_process_name(name: &str) -> c_int {
        let mut buf = [0u8; 20];
        let mut len = 0usize;
        for (dst, &b) in buf[..19].iter_mut().zip(name.as_bytes().iter()) {
            if b == 0 {
                break;
            }
            *dst = b;
            len += 1;
        }
        unsafe {
            let saved = *__error();
            let ret = syscall6(SYS_THR_SET_NAME, [(-1i64) as u64, buf.as_ptr() as u64, 0, 0, 0, 0]);
            let pid = syscall6(SYS_GETPID, [0; 6]) as i32;
            let mib: [i32; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_ARGS, pid];
            let _ = syscall6(
                SYS___SYSCTL,
                [
                    mib.as_ptr() as u64,
                    4,
                    0,
                    0,
                    buf.as_ptr() as u64,
                    (len + 1) as u64,
                ],
            );
            *__error() = saved;
            ret as c_int
        }
    }

    /// Redirects stdin/stdout/stderr to `/dev/null` so `pldmgr` / `elfldr`
    /// launchers receive immediate EOF after daemon startup.
    pub fn detach_stdio() {
        unsafe {
            let saved = *__error();
            let fd = syscall6(
                SYS_OPEN,
                [
                    b"/dev/null\0".as_ptr() as u64,
                    (O_RDWR | O_CLOEXEC) as u64,
                    0,
                    0,
                    0,
                    0,
                ],
            ) as c_int;
            if fd >= 0 {
                let _ = syscall6(SYS_DUP2, [fd as u64, 0, 0, 0, 0, 0]);
                let _ = syscall6(SYS_DUP2, [fd as u64, 1, 0, 0, 0, 0]);
                let _ = syscall6(SYS_DUP2, [fd as u64, 2, 0, 0, 0, 0]);
                if fd > 2 {
                    sys_close(fd);
                }
            }
            *__error() = saved;
        }
    }

    pub fn kernel_boot_time_secs() -> Option<i64> {
        let mib: [i32; 2] = [CTL_KERN, KERN_BOOTTIME];
        let mut tv = Timeval { sec: 0, usec: 0 };
        let mut len = core::mem::size_of::<Timeval>();
        let ret = unsafe {
            syscall6(
                SYS___SYSCTL,
                [
                    mib.as_ptr() as u64,
                    2,
                    &mut tv as *mut _ as u64,
                    &mut len as *mut _ as u64,
                    0,
                    0,
                ],
            )
        };
        if ret == 0 && len == core::mem::size_of::<Timeval>() && tv.sec > 0 {
            Some(tv.sec)
        } else {
            None
        }
    }

    fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    }

    pub fn is_pid_openbot(pid: i32) -> bool {
        if pid <= 1 {
            return false;
        }
        let mut buf = [0u8; 2048];
        let mib: [i32; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];
        let mut len = buf.len();
        let ret = unsafe {
            syscall6(
                SYS___SYSCTL,
                [
                    mib.as_ptr() as u64,
                    4,
                    buf.as_mut_ptr() as u64,
                    &mut len as *mut _ as u64,
                    0,
                    0,
                ],
            )
        };
        if ret != 0 || len == 0 {
            return false;
        }
        let data = &buf[..len.min(buf.len())];
        contains_ascii_ci(data, b"ps5-openbot") || contains_ascii_ci(data, b"openbot-port-server")
    }
}

#[cfg(target_vendor = "sie")]
pub use rt_impl::*;
