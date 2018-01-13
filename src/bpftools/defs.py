import re


def parse_defs(scope, defines):
    '''
    Parse CPP #defines of the basic form '#define [a-zA-Z0-9_] <some replacement><newline>'
    '''
    p_define = re.compile('^[\t ]*#[\t ]*define[\t ]+([a-zA-Z0-9_]+)[\t ]+(.*)$')
    p_comment = re.compile(r'/\*([^*]+|\*+[^/])*(\*+/)?')
    p_cpp_comment = re.compile('//.*')
    # remove comments
    defines = p_comment.sub(' ', defines)
    # remove continuation lines
    defines = defines.replace('\\\n', ' ')
    local_scope = dict(scope)
    defs = {}
    for ln in defines.splitlines():
        m = p_define.match(ln)
        if m:
            defs[m.group(1)] = eval(m.group(2), globals(), local_scope)
            local_scope[m.group(1)] = defs[m.group(1)]
    return defs


generic = {
    '__X32_SYSCALL_BIT': 0x40000000,
}
generic.update(parse_defs(generic, '''
#define EM_NONE		0
#define EM_M32		1
#define EM_SPARC	2
#define EM_386		3
#define EM_68K		4
#define EM_88K		5
#define EM_486		6	/* Perhaps disused */
#define EM_860		7
#define EM_MIPS		8	/* MIPS R3000 (officially, big-endian only) */
#define EM_MIPS_RS3_LE	10	/* MIPS R3000 little-endian */
#define EM_MIPS_RS4_BE	10	/* MIPS R4000 big-endian */

#define EM_PARISC	15	/* HPPA */
#define EM_SPARC32PLUS	18	/* Sun's "v8plus" */
#define EM_PPC		20	/* PowerPC */
#define EM_PPC64	21	 /* PowerPC64 */
#define EM_SPU		23	/* Cell BE SPU */
#define EM_ARM		40	/* ARM 32 bit */
#define EM_SH		42	/* SuperH */
#define EM_SPARCV9	43	/* SPARC v9 64-bit */
#define EM_H8_300	46	/* Renesas H8/300 */
#define EM_IA_64	50	/* HP/Intel IA-64 */
#define EM_X86_64	62	/* AMD x86-64 */
#define EM_S390		22	/* IBM S/390 */
#define EM_CRIS		76	/* Axis Communications 32-bit embedded processor */
#define EM_V850		87	/* NEC v850 */
#define EM_M32R		88	/* Renesas M32R */
#define EM_MN10300	89	/* Panasonic/MEI MN10300, AM33 */
#define EM_OPENRISC     92     /* OpenRISC 32-bit embedded processor */
#define EM_BLACKFIN     106     /* ADI Blackfin Processor */
#define EM_ALTERA_NIOS2	113	/* Altera Nios II soft-core processor */
#define EM_TI_C6000	140	/* TI C6X DSPs */
#define EM_AARCH64	183	/* ARM 64 bit */
#define EM_TILEPRO	188	/* Tilera TILEPro */
#define EM_MICROBLAZE	189	/* Xilinx MicroBlaze */
#define EM_TILEGX	191	/* Tilera TILE-Gx */
#define EM_FRV		0x5441	/* Fujitsu FR-V */
#define EM_AVR32	0x18ad	/* Atmel AVR32 */
/*
 * This is an interim value that we will use until the committee comes
 * up with a final number.
 */
#define EM_ALPHA	0x9026

/* Bogus old v850 magic number, used by old tools. */
#define EM_CYGNUS_V850	0x9080
/* Bogus old m32r magic number, used by old tools. */
#define EM_CYGNUS_M32R	0x9041
/* This is the old interim value for S/390 architecture */
#define EM_S390_OLD	0xA390
/* Also Panasonic/MEI MN10300, AM33 */
#define EM_CYGNUS_MN10300 0xbeef

#define __AUDIT_ARCH_CONVENTION_MASK 0x30000000
#define __AUDIT_ARCH_CONVENTION_MIPS64_N32 0x20000000

#define __AUDIT_ARCH_64BIT 0x80000000
#define __AUDIT_ARCH_LE	   0x40000000

#define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_ALPHA	(EM_ALPHA|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_ARM		(EM_ARM|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_ARMEB	(EM_ARM)
#define AUDIT_ARCH_CRIS		(EM_CRIS|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_FRV		(EM_FRV)
#define AUDIT_ARCH_I386		(EM_386|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_IA64		(EM_IA_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_M32R		(EM_M32R)
#define AUDIT_ARCH_M68K		(EM_68K)
#define AUDIT_ARCH_MICROBLAZE	(EM_MICROBLAZE)
#define AUDIT_ARCH_MIPS		(EM_MIPS)
#define AUDIT_ARCH_MIPSEL	(EM_MIPS|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_MIPS64	(EM_MIPS|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_MIPS64N32	(EM_MIPS|__AUDIT_ARCH_64BIT|\
                                __AUDIT_ARCH_CONVENTION_MIPS64_N32)
#define AUDIT_ARCH_MIPSEL64	(EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_MIPSEL64N32	(EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE|__AUDIT_ARCH_CONVENTION_MIPS64_N32)
#define AUDIT_ARCH_OPENRISC	(EM_OPENRISC)
#define AUDIT_ARCH_PARISC	(EM_PARISC)
#define AUDIT_ARCH_PARISC64	(EM_PARISC|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_PPC		(EM_PPC)
#define AUDIT_ARCH_PPC64	(EM_PPC64|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_PPC64LE	(EM_PPC64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_S390		(EM_S390)
#define AUDIT_ARCH_S390X	(EM_S390|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_SH		(EM_SH)
#define AUDIT_ARCH_SHEL		(EM_SH|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_SH64		(EM_SH|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_SHEL64	(EM_SH|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_SPARC	(EM_SPARC)
#define AUDIT_ARCH_SPARC64	(EM_SPARCV9|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_TILEGX	(EM_TILEGX|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_TILEGX32	(EM_TILEGX|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_TILEPRO	(EM_TILEPRO|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
'''))

arch_x86_64 = parse_defs(generic, '''
#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_close 3
#define __NR_stat 4
#define __NR_fstat 5
#define __NR_lstat 6
#define __NR_poll 7
#define __NR_lseek 8
#define __NR_mmap 9
#define __NR_mprotect 10
#define __NR_munmap 11
#define __NR_brk 12
#define __NR_rt_sigaction 13
#define __NR_rt_sigprocmask 14
#define __NR_rt_sigreturn 15
#define __NR_ioctl 16
#define __NR_pread64 17
#define __NR_pwrite64 18
#define __NR_readv 19
#define __NR_writev 20
#define __NR_access 21
#define __NR_pipe 22
#define __NR_select 23
#define __NR_sched_yield 24
#define __NR_mremap 25
#define __NR_msync 26
#define __NR_mincore 27
#define __NR_madvise 28
#define __NR_shmget 29
#define __NR_shmat 30
#define __NR_shmctl 31
#define __NR_dup 32
#define __NR_dup2 33
#define __NR_pause 34
#define __NR_nanosleep 35
#define __NR_getitimer 36
#define __NR_alarm 37
#define __NR_setitimer 38
#define __NR_getpid 39
#define __NR_sendfile 40
#define __NR_socket 41
#define __NR_connect 42
#define __NR_accept 43
#define __NR_sendto 44
#define __NR_recvfrom 45
#define __NR_sendmsg 46
#define __NR_recvmsg 47
#define __NR_shutdown 48
#define __NR_bind 49
#define __NR_listen 50
#define __NR_getsockname 51
#define __NR_getpeername 52
#define __NR_socketpair 53
#define __NR_setsockopt 54
#define __NR_getsockopt 55
#define __NR_clone 56
#define __NR_fork 57
#define __NR_vfork 58
#define __NR_execve 59
#define __NR_exit 60
#define __NR_wait4 61
#define __NR_kill 62
#define __NR_uname 63
#define __NR_semget 64
#define __NR_semop 65
#define __NR_semctl 66
#define __NR_shmdt 67
#define __NR_msgget 68
#define __NR_msgsnd 69
#define __NR_msgrcv 70
#define __NR_msgctl 71
#define __NR_fcntl 72
#define __NR_flock 73
#define __NR_fsync 74
#define __NR_fdatasync 75
#define __NR_truncate 76
#define __NR_ftruncate 77
#define __NR_getdents 78
#define __NR_getcwd 79
#define __NR_chdir 80
#define __NR_fchdir 81
#define __NR_rename 82
#define __NR_mkdir 83
#define __NR_rmdir 84
#define __NR_creat 85
#define __NR_link 86
#define __NR_unlink 87
#define __NR_symlink 88
#define __NR_readlink 89
#define __NR_chmod 90
#define __NR_fchmod 91
#define __NR_chown 92
#define __NR_fchown 93
#define __NR_lchown 94
#define __NR_umask 95
#define __NR_gettimeofday 96
#define __NR_getrlimit 97
#define __NR_getrusage 98
#define __NR_sysinfo 99
#define __NR_times 100
#define __NR_ptrace 101
#define __NR_getuid 102
#define __NR_syslog 103
#define __NR_getgid 104
#define __NR_setuid 105
#define __NR_setgid 106
#define __NR_geteuid 107
#define __NR_getegid 108
#define __NR_setpgid 109
#define __NR_getppid 110
#define __NR_getpgrp 111
#define __NR_setsid 112
#define __NR_setreuid 113
#define __NR_setregid 114
#define __NR_getgroups 115
#define __NR_setgroups 116
#define __NR_setresuid 117
#define __NR_getresuid 118
#define __NR_setresgid 119
#define __NR_getresgid 120
#define __NR_getpgid 121
#define __NR_setfsuid 122
#define __NR_setfsgid 123
#define __NR_getsid 124
#define __NR_capget 125
#define __NR_capset 126
#define __NR_rt_sigpending 127
#define __NR_rt_sigtimedwait 128
#define __NR_rt_sigqueueinfo 129
#define __NR_rt_sigsuspend 130
#define __NR_sigaltstack 131
#define __NR_utime 132
#define __NR_mknod 133
#define __NR_uselib 134
#define __NR_personality 135
#define __NR_ustat 136
#define __NR_statfs 137
#define __NR_fstatfs 138
#define __NR_sysfs 139
#define __NR_getpriority 140
#define __NR_setpriority 141
#define __NR_sched_setparam 142
#define __NR_sched_getparam 143
#define __NR_sched_setscheduler 144
#define __NR_sched_getscheduler 145
#define __NR_sched_get_priority_max 146
#define __NR_sched_get_priority_min 147
#define __NR_sched_rr_get_interval 148
#define __NR_mlock 149
#define __NR_munlock 150
#define __NR_mlockall 151
#define __NR_munlockall 152
#define __NR_vhangup 153
#define __NR_modify_ldt 154
#define __NR_pivot_root 155
#define __NR__sysctl 156
#define __NR_prctl 157
#define __NR_arch_prctl 158
#define __NR_adjtimex 159
#define __NR_setrlimit 160
#define __NR_chroot 161
#define __NR_sync 162
#define __NR_acct 163
#define __NR_settimeofday 164
#define __NR_mount 165
#define __NR_umount2 166
#define __NR_swapon 167
#define __NR_swapoff 168
#define __NR_reboot 169
#define __NR_sethostname 170
#define __NR_setdomainname 171
#define __NR_iopl 172
#define __NR_ioperm 173
#define __NR_create_module 174
#define __NR_init_module 175
#define __NR_delete_module 176
#define __NR_get_kernel_syms 177
#define __NR_query_module 178
#define __NR_quotactl 179
#define __NR_nfsservctl 180
#define __NR_getpmsg 181
#define __NR_putpmsg 182
#define __NR_afs_syscall 183
#define __NR_tuxcall 184
#define __NR_security 185
#define __NR_gettid 186
#define __NR_readahead 187
#define __NR_setxattr 188
#define __NR_lsetxattr 189
#define __NR_fsetxattr 190
#define __NR_getxattr 191
#define __NR_lgetxattr 192
#define __NR_fgetxattr 193
#define __NR_listxattr 194
#define __NR_llistxattr 195
#define __NR_flistxattr 196
#define __NR_removexattr 197
#define __NR_lremovexattr 198
#define __NR_fremovexattr 199
#define __NR_tkill 200
#define __NR_time 201
#define __NR_futex 202
#define __NR_sched_setaffinity 203
#define __NR_sched_getaffinity 204
#define __NR_set_thread_area 205
#define __NR_io_setup 206
#define __NR_io_destroy 207
#define __NR_io_getevents 208
#define __NR_io_submit 209
#define __NR_io_cancel 210
#define __NR_get_thread_area 211
#define __NR_lookup_dcookie 212
#define __NR_epoll_create 213
#define __NR_epoll_ctl_old 214
#define __NR_epoll_wait_old 215
#define __NR_remap_file_pages 216
#define __NR_getdents64 217
#define __NR_set_tid_address 218
#define __NR_restart_syscall 219
#define __NR_semtimedop 220
#define __NR_fadvise64 221
#define __NR_timer_create 222
#define __NR_timer_settime 223
#define __NR_timer_gettime 224
#define __NR_timer_getoverrun 225
#define __NR_timer_delete 226
#define __NR_clock_settime 227
#define __NR_clock_gettime 228
#define __NR_clock_getres 229
#define __NR_clock_nanosleep 230
#define __NR_exit_group 231
#define __NR_epoll_wait 232
#define __NR_epoll_ctl 233
#define __NR_tgkill 234
#define __NR_utimes 235
#define __NR_vserver 236
#define __NR_mbind 237
#define __NR_set_mempolicy 238
#define __NR_get_mempolicy 239
#define __NR_mq_open 240
#define __NR_mq_unlink 241
#define __NR_mq_timedsend 242
#define __NR_mq_timedreceive 243
#define __NR_mq_notify 244
#define __NR_mq_getsetattr 245
#define __NR_kexec_load 246
#define __NR_waitid 247
#define __NR_add_key 248
#define __NR_request_key 249
#define __NR_keyctl 250
#define __NR_ioprio_set 251
#define __NR_ioprio_get 252
#define __NR_inotify_init 253
#define __NR_inotify_add_watch 254
#define __NR_inotify_rm_watch 255
#define __NR_migrate_pages 256
#define __NR_openat 257
#define __NR_mkdirat 258
#define __NR_mknodat 259
#define __NR_fchownat 260
#define __NR_futimesat 261
#define __NR_newfstatat 262
#define __NR_unlinkat 263
#define __NR_renameat 264
#define __NR_linkat 265
#define __NR_symlinkat 266
#define __NR_readlinkat 267
#define __NR_fchmodat 268
#define __NR_faccessat 269
#define __NR_pselect6 270
#define __NR_ppoll 271
#define __NR_unshare 272
#define __NR_set_robust_list 273
#define __NR_get_robust_list 274
#define __NR_splice 275
#define __NR_tee 276
#define __NR_sync_file_range 277
#define __NR_vmsplice 278
#define __NR_move_pages 279
#define __NR_utimensat 280
#define __NR_epoll_pwait 281
#define __NR_signalfd 282
#define __NR_timerfd_create 283
#define __NR_eventfd 284
#define __NR_fallocate 285
#define __NR_timerfd_settime 286
#define __NR_timerfd_gettime 287
#define __NR_accept4 288
#define __NR_signalfd4 289
#define __NR_eventfd2 290
#define __NR_epoll_create1 291
#define __NR_dup3 292
#define __NR_pipe2 293
#define __NR_inotify_init1 294
#define __NR_preadv 295
#define __NR_pwritev 296
#define __NR_rt_tgsigqueueinfo 297
#define __NR_perf_event_open 298
#define __NR_recvmmsg 299
#define __NR_fanotify_init 300
#define __NR_fanotify_mark 301
#define __NR_prlimit64 302
#define __NR_name_to_handle_at 303
#define __NR_open_by_handle_at 304
#define __NR_clock_adjtime 305
#define __NR_syncfs 306
#define __NR_sendmmsg 307
#define __NR_setns 308
#define __NR_getcpu 309
#define __NR_process_vm_readv 310
#define __NR_process_vm_writev 311
#define __NR_kcmp 312
#define __NR_finit_module 313
#define __NR_sched_setattr 314
#define __NR_sched_getattr 315
#define __NR_renameat2 316
#define __NR_seccomp 317
#define __NR_getrandom 318
#define __NR_memfd_create 319
#define __NR_kexec_file_load 320
#define __NR_bpf 321
#define __NR_execveat 322
#define __NR_userfaultfd 323
#define __NR_membarrier 324
#define __NR_mlock2 325
''')


arch_i386 = parse_defs(generic, '''
#define __NR_restart_syscall 0
#define __NR_exit 1
#define __NR_fork 2
#define __NR_read 3
#define __NR_write 4
#define __NR_open 5
#define __NR_close 6
#define __NR_waitpid 7
#define __NR_creat 8
#define __NR_link 9
#define __NR_unlink 10
#define __NR_execve 11
#define __NR_chdir 12
#define __NR_time 13
#define __NR_mknod 14
#define __NR_chmod 15
#define __NR_lchown 16
#define __NR_break 17
#define __NR_oldstat 18
#define __NR_lseek 19
#define __NR_getpid 20
#define __NR_mount 21
#define __NR_umount 22
#define __NR_setuid 23
#define __NR_getuid 24
#define __NR_stime 25
#define __NR_ptrace 26
#define __NR_alarm 27
#define __NR_oldfstat 28
#define __NR_pause 29
#define __NR_utime 30
#define __NR_stty 31
#define __NR_gtty 32
#define __NR_access 33
#define __NR_nice 34
#define __NR_ftime 35
#define __NR_sync 36
#define __NR_kill 37
#define __NR_rename 38
#define __NR_mkdir 39
#define __NR_rmdir 40
#define __NR_dup 41
#define __NR_pipe 42
#define __NR_times 43
#define __NR_prof 44
#define __NR_brk 45
#define __NR_setgid 46
#define __NR_getgid 47
#define __NR_signal 48
#define __NR_geteuid 49
#define __NR_getegid 50
#define __NR_acct 51
#define __NR_umount2 52
#define __NR_lock 53
#define __NR_ioctl 54
#define __NR_fcntl 55
#define __NR_mpx 56
#define __NR_setpgid 57
#define __NR_ulimit 58
#define __NR_oldolduname 59
#define __NR_umask 60
#define __NR_chroot 61
#define __NR_ustat 62
#define __NR_dup2 63
#define __NR_getppid 64
#define __NR_getpgrp 65
#define __NR_setsid 66
#define __NR_sigaction 67
#define __NR_sgetmask 68
#define __NR_ssetmask 69
#define __NR_setreuid 70
#define __NR_setregid 71
#define __NR_sigsuspend 72
#define __NR_sigpending 73
#define __NR_sethostname 74
#define __NR_setrlimit 75
#define __NR_getrlimit 76
#define __NR_getrusage 77
#define __NR_gettimeofday 78
#define __NR_settimeofday 79
#define __NR_getgroups 80
#define __NR_setgroups 81
#define __NR_select 82
#define __NR_symlink 83
#define __NR_oldlstat 84
#define __NR_readlink 85
#define __NR_uselib 86
#define __NR_swapon 87
#define __NR_reboot 88
#define __NR_readdir 89
#define __NR_mmap 90
#define __NR_munmap 91
#define __NR_truncate 92
#define __NR_ftruncate 93
#define __NR_fchmod 94
#define __NR_fchown 95
#define __NR_getpriority 96
#define __NR_setpriority 97
#define __NR_profil 98
#define __NR_statfs 99
#define __NR_fstatfs 100
#define __NR_ioperm 101
#define __NR_socketcall 102
#define __NR_syslog 103
#define __NR_setitimer 104
#define __NR_getitimer 105
#define __NR_stat 106
#define __NR_lstat 107
#define __NR_fstat 108
#define __NR_olduname 109
#define __NR_iopl 110
#define __NR_vhangup 111
#define __NR_idle 112
#define __NR_vm86old 113
#define __NR_wait4 114
#define __NR_swapoff 115
#define __NR_sysinfo 116
#define __NR_ipc 117
#define __NR_fsync 118
#define __NR_sigreturn 119
#define __NR_clone 120
#define __NR_setdomainname 121
#define __NR_uname 122
#define __NR_modify_ldt 123
#define __NR_adjtimex 124
#define __NR_mprotect 125
#define __NR_sigprocmask 126
#define __NR_create_module 127
#define __NR_init_module 128
#define __NR_delete_module 129
#define __NR_get_kernel_syms 130
#define __NR_quotactl 131
#define __NR_getpgid 132
#define __NR_fchdir 133
#define __NR_bdflush 134
#define __NR_sysfs 135
#define __NR_personality 136
#define __NR_afs_syscall 137
#define __NR_setfsuid 138
#define __NR_setfsgid 139
#define __NR__llseek 140
#define __NR_getdents 141
#define __NR__newselect 142
#define __NR_flock 143
#define __NR_msync 144
#define __NR_readv 145
#define __NR_writev 146
#define __NR_getsid 147
#define __NR_fdatasync 148
#define __NR__sysctl 149
#define __NR_mlock 150
#define __NR_munlock 151
#define __NR_mlockall 152
#define __NR_munlockall 153
#define __NR_sched_setparam 154
#define __NR_sched_getparam 155
#define __NR_sched_setscheduler 156
#define __NR_sched_getscheduler 157
#define __NR_sched_yield 158
#define __NR_sched_get_priority_max 159
#define __NR_sched_get_priority_min 160
#define __NR_sched_rr_get_interval 161
#define __NR_nanosleep 162
#define __NR_mremap 163
#define __NR_setresuid 164
#define __NR_getresuid 165
#define __NR_vm86 166
#define __NR_query_module 167
#define __NR_poll 168
#define __NR_nfsservctl 169
#define __NR_setresgid 170
#define __NR_getresgid 171
#define __NR_prctl 172
#define __NR_rt_sigreturn 173
#define __NR_rt_sigaction 174
#define __NR_rt_sigprocmask 175
#define __NR_rt_sigpending 176
#define __NR_rt_sigtimedwait 177
#define __NR_rt_sigqueueinfo 178
#define __NR_rt_sigsuspend 179
#define __NR_pread64 180
#define __NR_pwrite64 181
#define __NR_chown 182
#define __NR_getcwd 183
#define __NR_capget 184
#define __NR_capset 185
#define __NR_sigaltstack 186
#define __NR_sendfile 187
#define __NR_getpmsg 188
#define __NR_putpmsg 189
#define __NR_vfork 190
#define __NR_ugetrlimit 191
#define __NR_mmap2 192
#define __NR_truncate64 193
#define __NR_ftruncate64 194
#define __NR_stat64 195
#define __NR_lstat64 196
#define __NR_fstat64 197
#define __NR_lchown32 198
#define __NR_getuid32 199
#define __NR_getgid32 200
#define __NR_geteuid32 201
#define __NR_getegid32 202
#define __NR_setreuid32 203
#define __NR_setregid32 204
#define __NR_getgroups32 205
#define __NR_setgroups32 206
#define __NR_fchown32 207
#define __NR_setresuid32 208
#define __NR_getresuid32 209
#define __NR_setresgid32 210
#define __NR_getresgid32 211
#define __NR_chown32 212
#define __NR_setuid32 213
#define __NR_setgid32 214
#define __NR_setfsuid32 215
#define __NR_setfsgid32 216
#define __NR_pivot_root 217
#define __NR_mincore 218
#define __NR_madvise 219
#define __NR_getdents64 220
#define __NR_fcntl64 221
#define __NR_gettid 224
#define __NR_readahead 225
#define __NR_setxattr 226
#define __NR_lsetxattr 227
#define __NR_fsetxattr 228
#define __NR_getxattr 229
#define __NR_lgetxattr 230
#define __NR_fgetxattr 231
#define __NR_listxattr 232
#define __NR_llistxattr 233
#define __NR_flistxattr 234
#define __NR_removexattr 235
#define __NR_lremovexattr 236
#define __NR_fremovexattr 237
#define __NR_tkill 238
#define __NR_sendfile64 239
#define __NR_futex 240
#define __NR_sched_setaffinity 241
#define __NR_sched_getaffinity 242
#define __NR_set_thread_area 243
#define __NR_get_thread_area 244
#define __NR_io_setup 245
#define __NR_io_destroy 246
#define __NR_io_getevents 247
#define __NR_io_submit 248
#define __NR_io_cancel 249
#define __NR_fadvise64 250
#define __NR_exit_group 252
#define __NR_lookup_dcookie 253
#define __NR_epoll_create 254
#define __NR_epoll_ctl 255
#define __NR_epoll_wait 256
#define __NR_remap_file_pages 257
#define __NR_set_tid_address 258
#define __NR_timer_create 259
#define __NR_timer_settime 260
#define __NR_timer_gettime 261
#define __NR_timer_getoverrun 262
#define __NR_timer_delete 263
#define __NR_clock_settime 264
#define __NR_clock_gettime 265
#define __NR_clock_getres 266
#define __NR_clock_nanosleep 267
#define __NR_statfs64 268
#define __NR_fstatfs64 269
#define __NR_tgkill 270
#define __NR_utimes 271
#define __NR_fadvise64_64 272
#define __NR_vserver 273
#define __NR_mbind 274
#define __NR_get_mempolicy 275
#define __NR_set_mempolicy 276
#define __NR_mq_open 277
#define __NR_mq_unlink 278
#define __NR_mq_timedsend 279
#define __NR_mq_timedreceive 280
#define __NR_mq_notify 281
#define __NR_mq_getsetattr 282
#define __NR_kexec_load 283
#define __NR_waitid 284
#define __NR_add_key 286
#define __NR_request_key 287
#define __NR_keyctl 288
#define __NR_ioprio_set 289
#define __NR_ioprio_get 290
#define __NR_inotify_init 291
#define __NR_inotify_add_watch 292
#define __NR_inotify_rm_watch 293
#define __NR_migrate_pages 294
#define __NR_openat 295
#define __NR_mkdirat 296
#define __NR_mknodat 297
#define __NR_fchownat 298
#define __NR_futimesat 299
#define __NR_fstatat64 300
#define __NR_unlinkat 301
#define __NR_renameat 302
#define __NR_linkat 303
#define __NR_symlinkat 304
#define __NR_readlinkat 305
#define __NR_fchmodat 306
#define __NR_faccessat 307
#define __NR_pselect6 308
#define __NR_ppoll 309
#define __NR_unshare 310
#define __NR_set_robust_list 311
#define __NR_get_robust_list 312
#define __NR_splice 313
#define __NR_sync_file_range 314
#define __NR_tee 315
#define __NR_vmsplice 316
#define __NR_move_pages 317
#define __NR_getcpu 318
#define __NR_epoll_pwait 319
#define __NR_utimensat 320
#define __NR_signalfd 321
#define __NR_timerfd_create 322
#define __NR_eventfd 323
#define __NR_fallocate 324
#define __NR_timerfd_settime 325
#define __NR_timerfd_gettime 326
#define __NR_signalfd4 327
#define __NR_eventfd2 328
#define __NR_epoll_create1 329
#define __NR_dup3 330
#define __NR_pipe2 331
#define __NR_inotify_init1 332
#define __NR_preadv 333
#define __NR_pwritev 334
#define __NR_rt_tgsigqueueinfo 335
#define __NR_perf_event_open 336
#define __NR_recvmmsg 337
#define __NR_fanotify_init 338
#define __NR_fanotify_mark 339
#define __NR_prlimit64 340
#define __NR_name_to_handle_at 341
#define __NR_open_by_handle_at 342
#define __NR_clock_adjtime 343
#define __NR_syncfs 344
#define __NR_sendmmsg 345
#define __NR_setns 346
#define __NR_process_vm_readv 347
#define __NR_process_vm_writev 348
#define __NR_kcmp 349
#define __NR_finit_module 350
#define __NR_sched_setattr 351
#define __NR_sched_getattr 352
#define __NR_renameat2 353
#define __NR_seccomp 354
#define __NR_getrandom 355
#define __NR_memfd_create 356
#define __NR_bpf 357
#define __NR_execveat 358
#define __NR_socket 359
#define __NR_socketpair 360
#define __NR_bind 361
#define __NR_connect 362
#define __NR_listen 363
#define __NR_accept4 364
#define __NR_getsockopt 365
#define __NR_setsockopt 366
#define __NR_getsockname 367
#define __NR_getpeername 368
#define __NR_sendto 369
#define __NR_sendmsg 370
#define __NR_recvfrom 371
#define __NR_recvmsg 372
#define __NR_shutdown 373
#define __NR_userfaultfd 374
#define __NR_membarrier 375
#define __NR_mlock2 376
''')

arch_x32 = parse_defs(generic, '''
#define __NR_read (__X32_SYSCALL_BIT + 0)
#define __NR_write (__X32_SYSCALL_BIT + 1)
#define __NR_open (__X32_SYSCALL_BIT + 2)
#define __NR_close (__X32_SYSCALL_BIT + 3)
#define __NR_stat (__X32_SYSCALL_BIT + 4)
#define __NR_fstat (__X32_SYSCALL_BIT + 5)
#define __NR_lstat (__X32_SYSCALL_BIT + 6)
#define __NR_poll (__X32_SYSCALL_BIT + 7)
#define __NR_lseek (__X32_SYSCALL_BIT + 8)
#define __NR_mmap (__X32_SYSCALL_BIT + 9)
#define __NR_mprotect (__X32_SYSCALL_BIT + 10)
#define __NR_munmap (__X32_SYSCALL_BIT + 11)
#define __NR_brk (__X32_SYSCALL_BIT + 12)
#define __NR_rt_sigprocmask (__X32_SYSCALL_BIT + 14)
#define __NR_pread64 (__X32_SYSCALL_BIT + 17)
#define __NR_pwrite64 (__X32_SYSCALL_BIT + 18)
#define __NR_access (__X32_SYSCALL_BIT + 21)
#define __NR_pipe (__X32_SYSCALL_BIT + 22)
#define __NR_select (__X32_SYSCALL_BIT + 23)
#define __NR_sched_yield (__X32_SYSCALL_BIT + 24)
#define __NR_mremap (__X32_SYSCALL_BIT + 25)
#define __NR_msync (__X32_SYSCALL_BIT + 26)
#define __NR_mincore (__X32_SYSCALL_BIT + 27)
#define __NR_madvise (__X32_SYSCALL_BIT + 28)
#define __NR_shmget (__X32_SYSCALL_BIT + 29)
#define __NR_shmat (__X32_SYSCALL_BIT + 30)
#define __NR_shmctl (__X32_SYSCALL_BIT + 31)
#define __NR_dup (__X32_SYSCALL_BIT + 32)
#define __NR_dup2 (__X32_SYSCALL_BIT + 33)
#define __NR_pause (__X32_SYSCALL_BIT + 34)
#define __NR_nanosleep (__X32_SYSCALL_BIT + 35)
#define __NR_getitimer (__X32_SYSCALL_BIT + 36)
#define __NR_alarm (__X32_SYSCALL_BIT + 37)
#define __NR_setitimer (__X32_SYSCALL_BIT + 38)
#define __NR_getpid (__X32_SYSCALL_BIT + 39)
#define __NR_sendfile (__X32_SYSCALL_BIT + 40)
#define __NR_socket (__X32_SYSCALL_BIT + 41)
#define __NR_connect (__X32_SYSCALL_BIT + 42)
#define __NR_accept (__X32_SYSCALL_BIT + 43)
#define __NR_sendto (__X32_SYSCALL_BIT + 44)
#define __NR_shutdown (__X32_SYSCALL_BIT + 48)
#define __NR_bind (__X32_SYSCALL_BIT + 49)
#define __NR_listen (__X32_SYSCALL_BIT + 50)
#define __NR_getsockname (__X32_SYSCALL_BIT + 51)
#define __NR_getpeername (__X32_SYSCALL_BIT + 52)
#define __NR_socketpair (__X32_SYSCALL_BIT + 53)
#define __NR_clone (__X32_SYSCALL_BIT + 56)
#define __NR_fork (__X32_SYSCALL_BIT + 57)
#define __NR_vfork (__X32_SYSCALL_BIT + 58)
#define __NR_exit (__X32_SYSCALL_BIT + 60)
#define __NR_wait4 (__X32_SYSCALL_BIT + 61)
#define __NR_kill (__X32_SYSCALL_BIT + 62)
#define __NR_uname (__X32_SYSCALL_BIT + 63)
#define __NR_semget (__X32_SYSCALL_BIT + 64)
#define __NR_semop (__X32_SYSCALL_BIT + 65)
#define __NR_semctl (__X32_SYSCALL_BIT + 66)
#define __NR_shmdt (__X32_SYSCALL_BIT + 67)
#define __NR_msgget (__X32_SYSCALL_BIT + 68)
#define __NR_msgsnd (__X32_SYSCALL_BIT + 69)
#define __NR_msgrcv (__X32_SYSCALL_BIT + 70)
#define __NR_msgctl (__X32_SYSCALL_BIT + 71)
#define __NR_fcntl (__X32_SYSCALL_BIT + 72)
#define __NR_flock (__X32_SYSCALL_BIT + 73)
#define __NR_fsync (__X32_SYSCALL_BIT + 74)
#define __NR_fdatasync (__X32_SYSCALL_BIT + 75)
#define __NR_truncate (__X32_SYSCALL_BIT + 76)
#define __NR_ftruncate (__X32_SYSCALL_BIT + 77)
#define __NR_getdents (__X32_SYSCALL_BIT + 78)
#define __NR_getcwd (__X32_SYSCALL_BIT + 79)
#define __NR_chdir (__X32_SYSCALL_BIT + 80)
#define __NR_fchdir (__X32_SYSCALL_BIT + 81)
#define __NR_rename (__X32_SYSCALL_BIT + 82)
#define __NR_mkdir (__X32_SYSCALL_BIT + 83)
#define __NR_rmdir (__X32_SYSCALL_BIT + 84)
#define __NR_creat (__X32_SYSCALL_BIT + 85)
#define __NR_link (__X32_SYSCALL_BIT + 86)
#define __NR_unlink (__X32_SYSCALL_BIT + 87)
#define __NR_symlink (__X32_SYSCALL_BIT + 88)
#define __NR_readlink (__X32_SYSCALL_BIT + 89)
#define __NR_chmod (__X32_SYSCALL_BIT + 90)
#define __NR_fchmod (__X32_SYSCALL_BIT + 91)
#define __NR_chown (__X32_SYSCALL_BIT + 92)
#define __NR_fchown (__X32_SYSCALL_BIT + 93)
#define __NR_lchown (__X32_SYSCALL_BIT + 94)
#define __NR_umask (__X32_SYSCALL_BIT + 95)
#define __NR_gettimeofday (__X32_SYSCALL_BIT + 96)
#define __NR_getrlimit (__X32_SYSCALL_BIT + 97)
#define __NR_getrusage (__X32_SYSCALL_BIT + 98)
#define __NR_sysinfo (__X32_SYSCALL_BIT + 99)
#define __NR_times (__X32_SYSCALL_BIT + 100)
#define __NR_getuid (__X32_SYSCALL_BIT + 102)
#define __NR_syslog (__X32_SYSCALL_BIT + 103)
#define __NR_getgid (__X32_SYSCALL_BIT + 104)
#define __NR_setuid (__X32_SYSCALL_BIT + 105)
#define __NR_setgid (__X32_SYSCALL_BIT + 106)
#define __NR_geteuid (__X32_SYSCALL_BIT + 107)
#define __NR_getegid (__X32_SYSCALL_BIT + 108)
#define __NR_setpgid (__X32_SYSCALL_BIT + 109)
#define __NR_getppid (__X32_SYSCALL_BIT + 110)
#define __NR_getpgrp (__X32_SYSCALL_BIT + 111)
#define __NR_setsid (__X32_SYSCALL_BIT + 112)
#define __NR_setreuid (__X32_SYSCALL_BIT + 113)
#define __NR_setregid (__X32_SYSCALL_BIT + 114)
#define __NR_getgroups (__X32_SYSCALL_BIT + 115)
#define __NR_setgroups (__X32_SYSCALL_BIT + 116)
#define __NR_setresuid (__X32_SYSCALL_BIT + 117)
#define __NR_getresuid (__X32_SYSCALL_BIT + 118)
#define __NR_setresgid (__X32_SYSCALL_BIT + 119)
#define __NR_getresgid (__X32_SYSCALL_BIT + 120)
#define __NR_getpgid (__X32_SYSCALL_BIT + 121)
#define __NR_setfsuid (__X32_SYSCALL_BIT + 122)
#define __NR_setfsgid (__X32_SYSCALL_BIT + 123)
#define __NR_getsid (__X32_SYSCALL_BIT + 124)
#define __NR_capget (__X32_SYSCALL_BIT + 125)
#define __NR_capset (__X32_SYSCALL_BIT + 126)
#define __NR_rt_sigsuspend (__X32_SYSCALL_BIT + 130)
#define __NR_utime (__X32_SYSCALL_BIT + 132)
#define __NR_mknod (__X32_SYSCALL_BIT + 133)
#define __NR_personality (__X32_SYSCALL_BIT + 135)
#define __NR_ustat (__X32_SYSCALL_BIT + 136)
#define __NR_statfs (__X32_SYSCALL_BIT + 137)
#define __NR_fstatfs (__X32_SYSCALL_BIT + 138)
#define __NR_sysfs (__X32_SYSCALL_BIT + 139)
#define __NR_getpriority (__X32_SYSCALL_BIT + 140)
#define __NR_setpriority (__X32_SYSCALL_BIT + 141)
#define __NR_sched_setparam (__X32_SYSCALL_BIT + 142)
#define __NR_sched_getparam (__X32_SYSCALL_BIT + 143)
#define __NR_sched_setscheduler (__X32_SYSCALL_BIT + 144)
#define __NR_sched_getscheduler (__X32_SYSCALL_BIT + 145)
#define __NR_sched_get_priority_max (__X32_SYSCALL_BIT + 146)
#define __NR_sched_get_priority_min (__X32_SYSCALL_BIT + 147)
#define __NR_sched_rr_get_interval (__X32_SYSCALL_BIT + 148)
#define __NR_mlock (__X32_SYSCALL_BIT + 149)
#define __NR_munlock (__X32_SYSCALL_BIT + 150)
#define __NR_mlockall (__X32_SYSCALL_BIT + 151)
#define __NR_munlockall (__X32_SYSCALL_BIT + 152)
#define __NR_vhangup (__X32_SYSCALL_BIT + 153)
#define __NR_modify_ldt (__X32_SYSCALL_BIT + 154)
#define __NR_pivot_root (__X32_SYSCALL_BIT + 155)
#define __NR_prctl (__X32_SYSCALL_BIT + 157)
#define __NR_arch_prctl (__X32_SYSCALL_BIT + 158)
#define __NR_adjtimex (__X32_SYSCALL_BIT + 159)
#define __NR_setrlimit (__X32_SYSCALL_BIT + 160)
#define __NR_chroot (__X32_SYSCALL_BIT + 161)
#define __NR_sync (__X32_SYSCALL_BIT + 162)
#define __NR_acct (__X32_SYSCALL_BIT + 163)
#define __NR_settimeofday (__X32_SYSCALL_BIT + 164)
#define __NR_mount (__X32_SYSCALL_BIT + 165)
#define __NR_umount2 (__X32_SYSCALL_BIT + 166)
#define __NR_swapon (__X32_SYSCALL_BIT + 167)
#define __NR_swapoff (__X32_SYSCALL_BIT + 168)
#define __NR_reboot (__X32_SYSCALL_BIT + 169)
#define __NR_sethostname (__X32_SYSCALL_BIT + 170)
#define __NR_setdomainname (__X32_SYSCALL_BIT + 171)
#define __NR_iopl (__X32_SYSCALL_BIT + 172)
#define __NR_ioperm (__X32_SYSCALL_BIT + 173)
#define __NR_init_module (__X32_SYSCALL_BIT + 175)
#define __NR_delete_module (__X32_SYSCALL_BIT + 176)
#define __NR_quotactl (__X32_SYSCALL_BIT + 179)
#define __NR_getpmsg (__X32_SYSCALL_BIT + 181)
#define __NR_putpmsg (__X32_SYSCALL_BIT + 182)
#define __NR_afs_syscall (__X32_SYSCALL_BIT + 183)
#define __NR_tuxcall (__X32_SYSCALL_BIT + 184)
#define __NR_security (__X32_SYSCALL_BIT + 185)
#define __NR_gettid (__X32_SYSCALL_BIT + 186)
#define __NR_readahead (__X32_SYSCALL_BIT + 187)
#define __NR_setxattr (__X32_SYSCALL_BIT + 188)
#define __NR_lsetxattr (__X32_SYSCALL_BIT + 189)
#define __NR_fsetxattr (__X32_SYSCALL_BIT + 190)
#define __NR_getxattr (__X32_SYSCALL_BIT + 191)
#define __NR_lgetxattr (__X32_SYSCALL_BIT + 192)
#define __NR_fgetxattr (__X32_SYSCALL_BIT + 193)
#define __NR_listxattr (__X32_SYSCALL_BIT + 194)
#define __NR_llistxattr (__X32_SYSCALL_BIT + 195)
#define __NR_flistxattr (__X32_SYSCALL_BIT + 196)
#define __NR_removexattr (__X32_SYSCALL_BIT + 197)
#define __NR_lremovexattr (__X32_SYSCALL_BIT + 198)
#define __NR_fremovexattr (__X32_SYSCALL_BIT + 199)
#define __NR_tkill (__X32_SYSCALL_BIT + 200)
#define __NR_time (__X32_SYSCALL_BIT + 201)
#define __NR_futex (__X32_SYSCALL_BIT + 202)
#define __NR_sched_setaffinity (__X32_SYSCALL_BIT + 203)
#define __NR_sched_getaffinity (__X32_SYSCALL_BIT + 204)
#define __NR_io_destroy (__X32_SYSCALL_BIT + 207)
#define __NR_io_getevents (__X32_SYSCALL_BIT + 208)
#define __NR_io_cancel (__X32_SYSCALL_BIT + 210)
#define __NR_lookup_dcookie (__X32_SYSCALL_BIT + 212)
#define __NR_epoll_create (__X32_SYSCALL_BIT + 213)
#define __NR_remap_file_pages (__X32_SYSCALL_BIT + 216)
#define __NR_getdents64 (__X32_SYSCALL_BIT + 217)
#define __NR_set_tid_address (__X32_SYSCALL_BIT + 218)
#define __NR_restart_syscall (__X32_SYSCALL_BIT + 219)
#define __NR_semtimedop (__X32_SYSCALL_BIT + 220)
#define __NR_fadvise64 (__X32_SYSCALL_BIT + 221)
#define __NR_timer_settime (__X32_SYSCALL_BIT + 223)
#define __NR_timer_gettime (__X32_SYSCALL_BIT + 224)
#define __NR_timer_getoverrun (__X32_SYSCALL_BIT + 225)
#define __NR_timer_delete (__X32_SYSCALL_BIT + 226)
#define __NR_clock_settime (__X32_SYSCALL_BIT + 227)
#define __NR_clock_gettime (__X32_SYSCALL_BIT + 228)
#define __NR_clock_getres (__X32_SYSCALL_BIT + 229)
#define __NR_clock_nanosleep (__X32_SYSCALL_BIT + 230)
#define __NR_exit_group (__X32_SYSCALL_BIT + 231)
#define __NR_epoll_wait (__X32_SYSCALL_BIT + 232)
#define __NR_epoll_ctl (__X32_SYSCALL_BIT + 233)
#define __NR_tgkill (__X32_SYSCALL_BIT + 234)
#define __NR_utimes (__X32_SYSCALL_BIT + 235)
#define __NR_mbind (__X32_SYSCALL_BIT + 237)
#define __NR_set_mempolicy (__X32_SYSCALL_BIT + 238)
#define __NR_get_mempolicy (__X32_SYSCALL_BIT + 239)
#define __NR_mq_open (__X32_SYSCALL_BIT + 240)
#define __NR_mq_unlink (__X32_SYSCALL_BIT + 241)
#define __NR_mq_timedsend (__X32_SYSCALL_BIT + 242)
#define __NR_mq_timedreceive (__X32_SYSCALL_BIT + 243)
#define __NR_mq_getsetattr (__X32_SYSCALL_BIT + 245)
#define __NR_add_key (__X32_SYSCALL_BIT + 248)
#define __NR_request_key (__X32_SYSCALL_BIT + 249)
#define __NR_keyctl (__X32_SYSCALL_BIT + 250)
#define __NR_ioprio_set (__X32_SYSCALL_BIT + 251)
#define __NR_ioprio_get (__X32_SYSCALL_BIT + 252)
#define __NR_inotify_init (__X32_SYSCALL_BIT + 253)
#define __NR_inotify_add_watch (__X32_SYSCALL_BIT + 254)
#define __NR_inotify_rm_watch (__X32_SYSCALL_BIT + 255)
#define __NR_migrate_pages (__X32_SYSCALL_BIT + 256)
#define __NR_openat (__X32_SYSCALL_BIT + 257)
#define __NR_mkdirat (__X32_SYSCALL_BIT + 258)
#define __NR_mknodat (__X32_SYSCALL_BIT + 259)
#define __NR_fchownat (__X32_SYSCALL_BIT + 260)
#define __NR_futimesat (__X32_SYSCALL_BIT + 261)
#define __NR_newfstatat (__X32_SYSCALL_BIT + 262)
#define __NR_unlinkat (__X32_SYSCALL_BIT + 263)
#define __NR_renameat (__X32_SYSCALL_BIT + 264)
#define __NR_linkat (__X32_SYSCALL_BIT + 265)
#define __NR_symlinkat (__X32_SYSCALL_BIT + 266)
#define __NR_readlinkat (__X32_SYSCALL_BIT + 267)
#define __NR_fchmodat (__X32_SYSCALL_BIT + 268)
#define __NR_faccessat (__X32_SYSCALL_BIT + 269)
#define __NR_pselect6 (__X32_SYSCALL_BIT + 270)
#define __NR_ppoll (__X32_SYSCALL_BIT + 271)
#define __NR_unshare (__X32_SYSCALL_BIT + 272)
#define __NR_splice (__X32_SYSCALL_BIT + 275)
#define __NR_tee (__X32_SYSCALL_BIT + 276)
#define __NR_sync_file_range (__X32_SYSCALL_BIT + 277)
#define __NR_utimensat (__X32_SYSCALL_BIT + 280)
#define __NR_epoll_pwait (__X32_SYSCALL_BIT + 281)
#define __NR_signalfd (__X32_SYSCALL_BIT + 282)
#define __NR_timerfd_create (__X32_SYSCALL_BIT + 283)
#define __NR_eventfd (__X32_SYSCALL_BIT + 284)
#define __NR_fallocate (__X32_SYSCALL_BIT + 285)
#define __NR_timerfd_settime (__X32_SYSCALL_BIT + 286)
#define __NR_timerfd_gettime (__X32_SYSCALL_BIT + 287)
#define __NR_accept4 (__X32_SYSCALL_BIT + 288)
#define __NR_signalfd4 (__X32_SYSCALL_BIT + 289)
#define __NR_eventfd2 (__X32_SYSCALL_BIT + 290)
#define __NR_epoll_create1 (__X32_SYSCALL_BIT + 291)
#define __NR_dup3 (__X32_SYSCALL_BIT + 292)
#define __NR_pipe2 (__X32_SYSCALL_BIT + 293)
#define __NR_inotify_init1 (__X32_SYSCALL_BIT + 294)
#define __NR_perf_event_open (__X32_SYSCALL_BIT + 298)
#define __NR_fanotify_init (__X32_SYSCALL_BIT + 300)
#define __NR_fanotify_mark (__X32_SYSCALL_BIT + 301)
#define __NR_prlimit64 (__X32_SYSCALL_BIT + 302)
#define __NR_name_to_handle_at (__X32_SYSCALL_BIT + 303)
#define __NR_open_by_handle_at (__X32_SYSCALL_BIT + 304)
#define __NR_clock_adjtime (__X32_SYSCALL_BIT + 305)
#define __NR_syncfs (__X32_SYSCALL_BIT + 306)
#define __NR_setns (__X32_SYSCALL_BIT + 308)
#define __NR_getcpu (__X32_SYSCALL_BIT + 309)
#define __NR_kcmp (__X32_SYSCALL_BIT + 312)
#define __NR_finit_module (__X32_SYSCALL_BIT + 313)
#define __NR_sched_setattr (__X32_SYSCALL_BIT + 314)
#define __NR_sched_getattr (__X32_SYSCALL_BIT + 315)
#define __NR_renameat2 (__X32_SYSCALL_BIT + 316)
#define __NR_seccomp (__X32_SYSCALL_BIT + 317)
#define __NR_getrandom (__X32_SYSCALL_BIT + 318)
#define __NR_memfd_create (__X32_SYSCALL_BIT + 319)
#define __NR_kexec_file_load (__X32_SYSCALL_BIT + 320)
#define __NR_bpf (__X32_SYSCALL_BIT + 321)
#define __NR_userfaultfd (__X32_SYSCALL_BIT + 323)
#define __NR_membarrier (__X32_SYSCALL_BIT + 324)
#define __NR_mlock2 (__X32_SYSCALL_BIT + 325)
#define __NR_rt_sigaction (__X32_SYSCALL_BIT + 512)
#define __NR_rt_sigreturn (__X32_SYSCALL_BIT + 513)
#define __NR_ioctl (__X32_SYSCALL_BIT + 514)
#define __NR_readv (__X32_SYSCALL_BIT + 515)
#define __NR_writev (__X32_SYSCALL_BIT + 516)
#define __NR_recvfrom (__X32_SYSCALL_BIT + 517)
#define __NR_sendmsg (__X32_SYSCALL_BIT + 518)
#define __NR_recvmsg (__X32_SYSCALL_BIT + 519)
#define __NR_execve (__X32_SYSCALL_BIT + 520)
#define __NR_ptrace (__X32_SYSCALL_BIT + 521)
#define __NR_rt_sigpending (__X32_SYSCALL_BIT + 522)
#define __NR_rt_sigtimedwait (__X32_SYSCALL_BIT + 523)
#define __NR_rt_sigqueueinfo (__X32_SYSCALL_BIT + 524)
#define __NR_sigaltstack (__X32_SYSCALL_BIT + 525)
#define __NR_timer_create (__X32_SYSCALL_BIT + 526)
#define __NR_mq_notify (__X32_SYSCALL_BIT + 527)
#define __NR_kexec_load (__X32_SYSCALL_BIT + 528)
#define __NR_waitid (__X32_SYSCALL_BIT + 529)
#define __NR_set_robust_list (__X32_SYSCALL_BIT + 530)
#define __NR_get_robust_list (__X32_SYSCALL_BIT + 531)
#define __NR_vmsplice (__X32_SYSCALL_BIT + 532)
#define __NR_move_pages (__X32_SYSCALL_BIT + 533)
#define __NR_preadv (__X32_SYSCALL_BIT + 534)
#define __NR_pwritev (__X32_SYSCALL_BIT + 535)
#define __NR_rt_tgsigqueueinfo (__X32_SYSCALL_BIT + 536)
#define __NR_recvmmsg (__X32_SYSCALL_BIT + 537)
#define __NR_sendmmsg (__X32_SYSCALL_BIT + 538)
#define __NR_process_vm_readv (__X32_SYSCALL_BIT + 539)
#define __NR_process_vm_writev (__X32_SYSCALL_BIT + 540)
#define __NR_setsockopt (__X32_SYSCALL_BIT + 541)
#define __NR_getsockopt (__X32_SYSCALL_BIT + 542)
#define __NR_io_setup (__X32_SYSCALL_BIT + 543)
#define __NR_io_submit (__X32_SYSCALL_BIT + 544)
#define __NR_execveat (__X32_SYSCALL_BIT + 545)
''')