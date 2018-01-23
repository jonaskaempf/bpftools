'''
Parsers for two variants of BPF syntax:

bpf_asm - classical BPF ASM syntax more or less as accepted by the Linux bpf_asm tool. Equivalent
    to the syntax outputted when disassembling in 'bpf' mode.
seccomp - Parse a human-friendly pseudo assembly listings specifically designed for seccomp type
    programs. Equivalent to the output of 'seccomp-' mode disassembly.

Both forms support labels including the magic 'next' label that means the next instruction (effectively
not a jump). Additionally, 'seccomp' parsing supports these extra features:

    * Constants are allowed in place of number literals. The set of
    valid constants are supplied to the 'lift' function and should
    corresponding to the chosen seccomp ABI.

    * Absolute loads (e.g. 'ld [0]', 'ldxb [4]', etc) can reference a pseudo struct 'data' representing
    the seccomp_data struct that is input to seccomp programs, e.g. 'ld [0]' can be written as 'A = data.nr'
'''
from __future__ import print_function, unicode_literals, absolute_import
import sys
from collections import namedtuple
from pyparsing import *
from bpftools.bpf import *


class ParseError(Exception): pass
class ParseTypeError(ParseError): pass


class Lbl(namedtuple('Lbl', 'label str loc')):
    def __str__(self):
        return '{}@({},{})'.format(self.label, lineno(self.loc, self.str), col(self.loc, self.str))
    __repr__ = __str__


lib = pyparsing_common

EOS = Suppress( StringEnd() )
comment = ';' + SkipTo( LineEnd() )
ign = Suppress
integer = (ign('0x') + lib.hex_integer) | lib.integer
int_literal = ign( Optional('#') ) + integer
comma = ign(',')
parens = lambda content: nestedExpr(opener='(', closer=')', content=content).setParseAction(lambda t: t[0])
brackets = lambda content: nestedExpr(opener='[', closer=']', content=content).setParseAction(lambda t: t[0])

var_name = lib.identifier
regA = ign( Optional('%') ) + Word('aA', exact=1)
regX = ign( Optional('%') ) + Word('xX', exact=1)
lbl = lib.identifier
offset = brackets(int_literal)

mode0 = regX
mode1 = offset
mode2 = brackets(ign(regX) + ign('+') + int_literal)
mode3 = ign('M') + offset
mode4 = int_literal
mode5 = ign('4') + ign('*') + parens(offset + ign('&') + ign('0xf'))
mode6 = lbl
mode7a = int_literal + comma + lbl + comma + lbl
# mode accepted by bpf_asm
mode7b = regX + comma + lbl + comma + lbl
mode8a = int_literal + comma + lbl
mode8b = regX + comma + lbl
mode9 = regA
# TODO mode10 - extensions

instr = (
# LOAD/STORE
      ('ldb'  + mode1).setParseAction(lambda t: (BPF_LD|BPF_B|BPF_ABS, 0, 0, t[1]))
    | ('ldb'  + mode2).setParseAction(lambda t: (BPF_LD|BPF_B|BPF_IND, 0, 0, t[1]))
    | ('ldh'  + mode1).setParseAction(lambda t: (BPF_LD|BPF_H|BPF_ABS, 0, 0, t[1]))
    | ('ldh'  + mode2).setParseAction(lambda t: (BPF_LD|BPF_H|BPF_IND, 0, 0, t[1]))
    | ('ldi'  + mode4).setParseAction(lambda t: (BPF_LD|BPF_W|BPF_IMM, 0, 0, t[1]))
    | ('ldxi' + mode4).setParseAction(lambda t: (BPF_LDX|BPF_W|BPF_IMM, 0, 0, t[1]))

    | ('ld'   + mode1).setParseAction(lambda t: (BPF_LD|BPF_W|BPF_ABS, 0, 0, t[1]))
    | ('ld'   + mode2).setParseAction(lambda t: (BPF_LD|BPF_W|BPF_IND, 0, 0, t[1]))
    | ('ld'   + mode3).setParseAction(lambda t: (BPF_LD|BPF_W|BPF_MEM, 0, 0, t[1]))
    | ('ld'   + mode4).setParseAction(lambda t: (BPF_LD|BPF_W|BPF_IMM, 0, 0, t[1]))

    | ('ldx'  + mode3).setParseAction(lambda t: (BPF_LDX|BPF_W|BPF_MEM, 0, 0, t[1]))
    | ('ldx'  + mode4).setParseAction(lambda t: (BPF_LDX|BPF_W|BPF_IMM, 0, 0, t[1]))
    | ('ldx'  + mode5).setParseAction(lambda t: (BPF_LDX|BPF_B|BPF_MSH, 0, 0, t[1]))
    | ('ldx'  + ign('len')).setParseAction(lambda t: (BPF_LDX|BPF_W|BPF_LEN, 0, 0, 0))
    | ('ldxb' + mode5).setParseAction(lambda t: (BPF_LDX|BPF_B|BPF_MSH, 0, 0, t[1]))

    | ('st'   + mode3).setParseAction(lambda t: (BPF_ST, 0, 0, t[1]))
    | ('stx'  + mode3).setParseAction(lambda t: (BPF_STX, 0, 0, t[1]))
    
# JUMP
    | ('jmp'  + mode6).setParseAction(lambda t: (BPF_JMP|BPF_JA, 0, 0, t[1]))
    | ('ja'  + mode6).setParseAction(lambda t: (BPF_JMP|BPF_JA, 0, 0, t[1]))

    | ('jeq'  + mode7a).setParseAction(lambda t: (BPF_JMP|BPF_JEQ|BPF_K, t[2], t[3], t[1]))
    | ('jeq'  + mode7b).setParseAction(lambda t: (BPF_JMP|BPF_JEQ|BPF_X, t[2], t[3], 0))
    | ('jeq'  + mode8a).setParseAction(lambda t: (BPF_JMP|BPF_JEQ|BPF_K, t[2], 0, t[1]))
    | ('jeq'  + mode8b).setParseAction(lambda t: (BPF_JMP|BPF_JEQ|BPF_X, t[2], 0, 0))

    | ('jneq' + mode8a).setParseAction(lambda t: (BPF_JMP|BPF_JEQ|BPF_K, 0, t[2], t[1]))
    | ('jneq' + mode8b).setParseAction(lambda t: (BPF_JMP|BPF_JEQ|BPF_X, 0, t[2], 0))

    | ('jlt'  + mode8a).setParseAction(lambda t: (BPF_JMP|BPF_JGE|BPF_K, 0, t[2], t[1]))
    | ('jlt'  + mode8b).setParseAction(lambda t: (BPF_JMP|BPF_JGE|BPF_X, 0, t[2], 0))

    | ('jle'  + mode8a).setParseAction(lambda t: (BPF_JMP|BPF_JGT|BPF_K, 0, t[2], t[1]))
    | ('jle'  + mode8b).setParseAction(lambda t: (BPF_JMP|BPF_JGT|BPF_X, 0, t[2], 0))

    | ('jgt'  + mode7a).setParseAction(lambda t: (BPF_JMP|BPF_JGT|BPF_K, t[2], t[3], t[1]))
    | ('jgt'  + mode7b).setParseAction(lambda t: (BPF_JMP|BPF_JGT|BPF_X, t[2], t[3], 0))
    | ('jgt'  + mode8a).setParseAction(lambda t: (BPF_JMP|BPF_JGT|BPF_K, t[2], 0, t[1]))
    | ('jgt'  + mode8b).setParseAction(lambda t: (BPF_JMP|BPF_JGT|BPF_X, t[2], 0, 0))

    | ('jge'  + mode7a).setParseAction(lambda t: (BPF_JMP|BPF_JGE|BPF_K, t[2], t[3], t[1]))
    | ('jge'  + mode7b).setParseAction(lambda t: (BPF_JMP|BPF_JGE|BPF_X, t[2], t[3], 0))
    | ('jge'  + mode8a).setParseAction(lambda t: (BPF_JMP|BPF_JGE|BPF_K, t[2], 0, t[1]))
    | ('jge'  + mode8b).setParseAction(lambda t: (BPF_JMP|BPF_JGE|BPF_X, t[2], 0, 0))

    | ('jset' + mode7a).setParseAction(lambda t: (BPF_JMP|BPF_JSET|BPF_K, t[2], t[3], t[1]))
    | ('jset' + mode7b).setParseAction(lambda t: (BPF_JMP|BPF_JSET|BPF_X, t[2], t[3], 0))
    | ('jset' + mode8a).setParseAction(lambda t: (BPF_JMP|BPF_JSET|BPF_K, t[2], 0, t[1]))
    | ('jset' + mode8b).setParseAction(lambda t: (BPF_JMP|BPF_JSET|BPF_X, t[2], 0, 0))

# ALU
    | ('add'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_ADD|BPF_X, 0, 0, 0))
    | ('add'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_ADD|BPF_K, 0, 0, t[1]))
    | ('sub'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_SUB|BPF_X, 0, 0, 0))
    | ('sub'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_SUB|BPF_K, 0, 0, t[1]))
    | ('mul'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_MUL|BPF_X, 0, 0, 0))
    | ('mul'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_MUL|BPF_K, 0, 0, t[1]))
    | ('div'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_DIV|BPF_X, 0, 0, 0))
    | ('div'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_DIV|BPF_K, 0, 0, t[1]))
    | ('mod'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_MOD|BPF_X, 0, 0, 0))
    | ('mod'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_MOD|BPF_K, 0, 0, t[1]))
    | Keyword('neg').setParseAction(lambda t: (BPF_ALU|BPF_NEG, 0, 0, 0))
    | ('and'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_AND|BPF_X, 0, 0, 0))
    | ('and'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_AND|BPF_K, 0, 0, t[1]))
    | ('or'   + mode0).setParseAction(lambda t: (BPF_ALU|BPF_OR|BPF_X, 0, 0, 0))
    | ('or'   + mode4).setParseAction(lambda t: (BPF_ALU|BPF_OR|BPF_K, 0, 0, t[1]))
    | ('xor'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_XOR|BPF_X, 0, 0, 0))
    | ('xor'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_XOR|BPF_K, 0, 0, t[1]))
    | ('lsh'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_LSH|BPF_X, 0, 0, 0))
    | ('lsh'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_LSH|BPF_K, 0, 0, t[1]))
    | ('rsh'  + mode0).setParseAction(lambda t: (BPF_ALU|BPF_RSH|BPF_X, 0, 0, 0))
    | ('rsh'  + mode4).setParseAction(lambda t: (BPF_ALU|BPF_RSH|BPF_K, 0, 0, t[1]))

# RET
    # this is accepted by bpf_asm, but is not in the docs
    | ('ret'  + mode0).setParseAction(lambda t: (BPF_RET|BPF_X, 0, 0, 0))
    | ('ret'  + mode4).setParseAction(lambda t: (BPF_RET|BPF_K, 0, 0, t[1]))
    | ('ret'  + mode9).setParseAction(lambda t: (BPF_RET|BPF_A, 0, 0, 0))

# MISC
    | Keyword('tax').setParseAction(lambda t: (BPF_MISC|BPF_TAX, 0, 0, 0))
    | Keyword('txa').setParseAction(lambda t: (BPF_MISC|BPF_TXA, 0, 0, 0))
)

labelled = lib.identifier + Suppress(':')
labelled_instr = labelled + instr
unlabelled_instr = instr

line = unlabelled_instr | labelled_instr
asm_prog = OneOrMore( line )
asm_prog.ignore(comment)

unlabelled_instr.setParseAction(lambda toks: (None, toks[0]))
labelled_instr.setParseAction(lambda s,loc,toks: (Lbl(toks[0], s, loc), toks[1][1]))

##
## Seccomp pseudo assembly syntax
##
mem = ign('M') + offset
lhs = regA | regX | mem

assign = EOS
arith = EOS
conditional = EOS
ret = 'return'


pseudo_prog = EOS

def parse_bpf_asm(s):
    '''Process string and convert into simplified, labelled instruction components'''
    return list(asm_prog.parseString(s))


def lift(labelled_instrs, constants={}):
    '''
    Post-process parser output into list of bpf.Instr by:

        - Resolve label addresses and replaces label references with relative offsets.
        - Assert that all jumps are forward jumps.
        - Replace constants with their values
    '''
    lbls, instrs = zip(*labelled_instrs)
    lbl_mapping = {}
    for pc, lbl in enumerate(lbls):
        if lbl is not None and lbl.label in lbl_mapping:
            raise ParseTypeError('Label {} conflicts with previous {}'.format(lbl, lbl_mapping[lbl.label][1]))
        elif lbl is not None:
            lbl_mapping[lbl.label] = (pc, lbl)

    def resolve_label(lbl, ref_pc):
        if isinstance(lbl, int):
            return lbl
        elif lbl == 'next':
            return 0
        elif lbl in lbl_mapping:
            lbl_pc = lbl_mapping[lbl][0]
            if ref_pc + 1 <= lbl_pc:
                return lbl_pc - ref_pc - 1
            else:
                raise ParseTypeError('Instr {} references label {} defined @ instr {}'.format(ref_pc, lbl, lbl_pc))
        else:
            raise ParseTypeError('Undefined label {} reference @ {:d}'.format(lbl, ref_pc))

    prog = []
    for pc, (opcode, jt, jf, k) in enumerate(instrs):
        jt = resolve_label(jt, pc)
        jf = resolve_label(jf, pc)
        if opcode == BPF_JMP|BPF_JA:
            k = resolve_label(k, pc)
        elif not isinstance(k, int):
            if k in constants:
                k = constants[k]
            else:
                raise ParseTypeError("Undefined 'k' value: '{}'".format(k))
        prog.append(Instr(opcode, jt, jf, k))
    
    return prog
