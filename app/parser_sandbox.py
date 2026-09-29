"""Linux parser-only seccomp boundary after imports, before hostile bytes.
Fail closed if filtering cannot be installed. This is defense in depth, not a VM.
"""
import ctypes,errno,sys

def restrict():
    if not sys.platform.startswith('linux'):return 'development-platform'
    lib=ctypes.CDLL('libseccomp.so.2',use_errno=True)
    lib.seccomp_init.argtypes=[ctypes.c_uint32];lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
    lib.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint];lib.seccomp_rule_add.restype=ctypes.c_int
    lib.seccomp_load.argtypes=[ctypes.c_void_p];lib.seccomp_load.restype=ctypes.c_int
    lib.seccomp_release.argtypes=[ctypes.c_void_p]
    ctx=lib.seccomp_init(0x7fff0000) # ALLOW; explicit syscall denial below
    if not ctx:raise RuntimeError('Sandbox unavailable')
    denied=('open','openat','openat2','creat','open_by_handle_at','name_to_handle_at',
      'socket','socketpair','connect','bind','listen','accept','accept4',
      'execve','execveat','fork','vfork','clone','clone3','ptrace','process_vm_readv','process_vm_writev',
      'pidfd_open','pidfd_getfd','io_uring_setup','io_uring_enter','io_uring_register',
      'mount','umount2','pivot_root','chroot','unshare','setns','bpf','perf_event_open',
      'open_tree','fsopen','fsconfig','fsmount','fspick','move_mount',
      'unlink','unlinkat','rename','renameat','renameat2','mkdir','mkdirat','rmdir',
      'link','linkat','symlink','symlinkat','chmod','fchmodat','chown','fchownat','truncate')
    try:
        for name in denied:
            nr=lib.seccomp_syscall_resolve_name(name.encode())
            if nr<0:
                if name in ('openat','socket','execve'):raise RuntimeError('Sandbox syscall unavailable')
                continue
            if lib.seccomp_rule_add(ctx,0x00050000|errno.EPERM,nr,0)!=0:raise RuntimeError('Sandbox rule failed')
        if lib.seccomp_load(ctx)!=0:raise RuntimeError('Sandbox installation failed')
    finally:lib.seccomp_release(ctx)
    return 'linux-seccomp'
