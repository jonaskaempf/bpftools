from __future__ import print_function
import sys
import argparse
from bpftools.bpf import u16, Instr, SeccompInstr, SimpleSeccompState
from bpftools.parser import parse_bpf_asm, lift


# Compat layer
if sys.version_info.major == 2:
    STDIN_BYTES = sys.stdin
    STDOUT_BYTES = sys.stdout
else:
    STDIN_BYTES = sys.stdin.buffer
    STDOUT_BYTES = sys.stdout.buffer


def disasm(bts, with_hexdump=True, context='bpf'):
    '''
    Get a disassembly listing as a string.

    bts - Bytes of a (e)BPF program
    context - the kind of BPF program (e.g. bpf, seccomp-<abi>)
    '''
    if context == 'bpf':
        prog = [Instr.from_bytes(bts[i:i+8]) for i in range(0, len(bts), 8)]
        out = [(instr.disasm(pc), instr.comment(pc), instr.hexdump()) for pc, instr in enumerate(prog)]

    elif context.startswith('seccomp-'):
        abi = context.lstrip('seccomp-')
        prog = [SeccompInstr.from_bytes(bts[i:i+8]) for i in range(0, len(bts), 8)]
        state = SimpleSeccompState(abi)
        out = []
        for instr in prog:
            out.append((instr.disasm(state), '', instr.hexdump()))
    
    lns = []
    for pc, (instr, comment, hexdump) in enumerate(out):
        comment = ' ; ' + comment if len(comment) > 0 else ''
        hexdump = '{:s} '.format(hexdump) if with_hexdump else ''
        lns.append('{:04d}: {:s}{:<20s}{:s}'.format(pc, hexdump, instr, comment))

    return '\n'.join(lns)


def parse(listing):
    step1 = parse_bpf_asm(listing)
    prog = lift(step1)
    return prog


def asm(listing):
    prog = parse(listing)
    return b''.join(p.asm() for p in prog)


##
## CLI commands
##

def _err(msg, *args, **kwargs):
    print(msg.format(*args, **kwargs), file=sys.stderr)


def _die(exit_code, msg, *args, **kwargs):
    _err(msg, *args, **kwargs)
    sys.exit(exit_code)


def _cmd_disasm(args):
    data = args.prog.read()
    # handle two types of program files: with short prog_len as header, and without
    if len(data) % 8 == 0:
        prog = data
    elif len(data[2:]) % 8 == 0 and u16(data[:2]) == len(data[2:]):
        prog = data[2:]
    else:
        _die(1, 'Cannot find a program in binary!')
    with_hexdump = not args.no_hexdump
    print(disasm(prog, with_hexdump=with_hexdump, context=args.vm_type))
        

def _cmd_asm(args):
    listing = args.prog.read()
    args.out.write(asm(listing))


def run_cli(cmd_args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--vm-type', 
        choices=['bpf', 'seccomp-i386', 'seccomp-x32', 'seccomp-x86_64'],
        default='bpf',
        help='Which BPF VM to apply.  Default: (generic) bpf')
    cmd_parsers = parser.add_subparsers(help='Commands')

    disasm = cmd_parsers.add_parser('disasm', help='Show disassembly listing')
    disasm.add_argument('--no-hexdump', action='store_true')
    disasm.add_argument('prog', nargs='?', default=sys.stdin, type=argparse.FileType('rb'))
    disasm.set_defaults(action=_cmd_disasm)

    asm = cmd_parsers.add_parser('asm', help='Assemble BPF program')
    asm.add_argument('prog', nargs='?', default=STDIN_BYTES, type=argparse.FileType('rb'))
    asm.add_argument('out', nargs='?', default=STDOUT_BYTES, type=argparse.FileType('wb'))
    asm.set_defaults(action=_cmd_asm)

    args = parser.parse_args(cmd_args)
    args.action(args)


def main():
    return run_cli()
