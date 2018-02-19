; forbid execve syscall
ld [arch]
jeq AUDIT_ARCH_X86_64, next, die
ld [data.nr]
jge __X32_SYSCALL_BIT, die, next
jeq SYS_execve, err, allow
err: ret ERRNO(1)
die: ret KILL
allow: ret ALLOW
