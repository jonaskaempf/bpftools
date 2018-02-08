# Installation

This repo contains a Python package and a BinaryNinja plugin. Clone this repo, and install the Python package:

```bash
$ python setup.py install
```

and optionally the BinaryNinja plugin:

```bash
$ ./install_binja.sh
```

Currently, the plugin does not rely on the installed Python package, but the installer creates a symlink to the package in the BinaryNinja plugins folder. I don't know how to make BinaryNinja smoothly integrate with Python virtualenvs, so it would not
readily support virtualenv installed packages.

# Usage

The Python package installs a module, `bpftools` and a commandline tool to it, `bpf`:

```bash
$ bpf -h
``` 

The `bpf` command currently supports assembly and disassembly. It has been written with a specific focus on the seccomp flavour
of bpf, so it supports disassembly into a more reader-friendly seccomp-specific assembler with known constants replaced with descriptive names. For example:


```bash
$ bpf -t seccomp-x86_64 disasm examples/forbid_execve.bpf 
; pc   op   jt   jf      k      instr
;-------------------------------------
0000: 0x20 0x00 0x00 0x00000004 A = data.arch       
0001: 0x15 0x00 0x04 0xc000003e (A == AUDIT_ARCH_X86_64) ? 0002 : 0006
0002: 0x20 0x00 0x00 0x00000000 A = data.nr         
0003: 0x35 0x02 0x00 0x40000000 (A >= __X32_SYSCALL_BIT) ? 0006
0004: 0x15 0x00 0x02 0x0000003b (A == SYS_execve) ? 0005 : 0007
0005: 0x06 0x00 0x00 0x00050001 return ERRNO(1)     
0006: 0x06 0x00 0x00 0x00000000 return KILL         
0007: 0x06 0x00 0x00 0x7fff0000 return ALLOW
```

Unfortunately, it does not yet support assembling this syntax, but it does support "vanilla" bpf syntax mixed with some seccomp specific constants.

# TODO

* Support seccomp-flavour syntax for assembly as well