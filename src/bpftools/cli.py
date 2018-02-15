from __future__ import print_function
import sys
import argparse
from bpftools.bpf import u16, Instr, SeccompInstr, SeccompABI, SimpleSeccompState
from bpftools.defs import generic, arch_i386, arch_x32, arch_x86_64
from bpftools.parser import parse_bpf_asm, lift


# Compat layer
if sys.version_info.major == 2:
    STDIN_TEXT = STDIN_BYTES = sys.stdin
    STDOUT_TEXT = STDOUT_BYTES = sys.stdout
else:
    STDIN_BYTES = sys.stdin.buffer
    STDOUT_BYTES = sys.stdout.buffer
    STDOUT_TEXT = sys.stdout
    STDIN_TEXT = sys.stdin


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


def parse(listing, macro_expander):
    step1 = parse_bpf_asm(listing)
    prog = lift(step1, macro_expander)
    return prog


def asm(listing, macro_expander):
    prog = parse(listing, macro_expander)
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
    '''
    Disassemble byte stream as BPF program.

    Optionally, the program bytes may be preceded by a short int specifying the program
    length in bytes
    '''
    data = args.prog.read()
    if len(data) % 8 == 0:
        prog = data
    elif len(data[2:]) % 8 == 0 and u16(data[:2]) == len(data[2:]):
        prog = data[2:]
    else:
        _die(1, 'No program found in {}'.format(args.prog))
    with_hexdump = not args.no_hexdump
    header = '; pc  ' + ('{:^4s} {:^4s} {:^4s} {:^10s}'.format('op', 'jt', 'jf', 'k') if with_hexdump else '') + ' instr' 
    header += '\n;' + '-'*(37 if with_hexdump else 11) + '\n'
    listing = disasm(prog, with_hexdump=with_hexdump, context=args.vm_type)

    args.out.write(header)
    args.out.write(listing)
    args.out.write('\n')
        

def _cmd_asm(args):
    listing = args.prog.read()
    if args.vm_type.startswith('seccomp'):
        arch = args.vm_type.split('-')[1]
        abi = SeccompABI(arch)
        offsets = {
            'nr': 0,
            'arch': 4,
            'instruction_pointer': 8,
            'args[0]': 0x10,
            'args[1]': 0x18,
            'args[2]': 0x20,
            'args[3]': 0x28,
            'args[4]': 0x30,
            'args[5]': 0x38,
        }
        def macro_expander(macro):
            return (
                abi.name_to_syscall.get(macro) or
                abi.name_to_audit.get(macro) or
                offsets.get(macro.lstrip('data.'))
            )
    else:
        macro_expander = lambda _: None

    args.out.write(asm(listing, macro_expander))


def run_cli(cmd_args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--vm-type', 
        choices=['bpf', 'seccomp-i386', 'seccomp-x32', 'seccomp-x86_64'],
        default='bpf',
        help='Which BPF VM to apply.  Default: (generic) bpf')
    cmd_parsers = parser.add_subparsers(help='Commands')

    disasm = cmd_parsers.add_parser('disasm', help='Generate disassembly listing')
    disasm.add_argument('--no-hexdump', action='store_true')
    disasm.add_argument('-o', '--out', help='Output file', default=STDOUT_TEXT, type=argparse.FileType('w'))
    disasm.add_argument('prog', nargs='?', default=STDIN_BYTES, type=argparse.FileType('rb'))
    disasm.set_defaults(action=_cmd_disasm)

    asm = cmd_parsers.add_parser('asm', help='Assemble BPF program')
    asm.add_argument('prog', nargs='?', default=STDIN_TEXT, type=argparse.FileType('r'))
    asm.add_argument('out', nargs='?', default=STDOUT_BYTES, type=argparse.FileType('wb'))
    asm.set_defaults(action=_cmd_asm)

    args = parser.parse_args(cmd_args)
    args.action(args)


def main():
    return run_cli()
