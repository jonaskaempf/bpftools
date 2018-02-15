; forbid execve syscall
ld [4]
jeq AUDIT_ARCH_X86_64, next, die
ld [0]
jge __X32_SYSCALL_BIT, die, next
jeq SYS_execve, err, allow
err: ret 0x00050001 ; ERRNO(1)
die: ret 0
allow: ret 0x7fff0000
