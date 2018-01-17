# coding: utf-8
from __future__ import print_function
import sys
import argparse
import struct
from struct import pack, unpack
from ctypes import c_uint32
from itertools import chain

from bpftools.defs import generic, arch_i386, arch_x32, arch_x86_64


''' Definitions in "linux/filter.h" '''
# Op class
def BPF_CLASS(code): return ((code) & 0x07)
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07

# /* ld/ldx fields */
def BPF_SIZE(code): return ((code) & 0x18)
BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10
def BPF_MODE(code): return ((code) & 0xe0)
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xa0

# /* alu/jmp fields */
def BPF_OP(code): return ((code) & 0xf0)
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_MOD = 0x90
BPF_XOR = 0xa0

BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40
def BPF_SRC(code): return ((code) & 0x08)
BPF_K = 0x00
BPF_X = 0x08

# /* ret - BPF_K and BPF_X also apply */
def BPF_RVAL(code): return ((code) & 0x18)
BPF_A = 0x10

# /* misc */
def BPF_MISCOP(code): return ((code) & 0xf8)
BPF_TAX = 0x00
BPF_TXA = 0x80

# All BPF instructions are sizeof(struct sock_filter) == 8
INSTR_SIZE = 8

Mnemonics = {
    # ignore 'ldi' which is alias to 'ld' with imm
    BPF_LD|BPF_W: 'ld',
    BPF_LD|BPF_H: 'ldh',
    BPF_LD|BPF_B: 'ldb',

    # ignore 'ldxi' which is alias to 'ldx' with imm
    BPF_LDX|BPF_W: 'ldx',
    BPF_LDX|BPF_B: 'ldxb',

    BPF_ST: 'st',
    BPF_STX: 'stx',

    BPF_ALU|BPF_ADD: 'add',
    BPF_ALU|BPF_SUB: 'sub',
    BPF_ALU|BPF_MUL: 'mul',
    BPF_ALU|BPF_DIV: 'div',
    BPF_ALU|BPF_OR: 'or',
    BPF_ALU|BPF_AND: 'and',
    BPF_ALU|BPF_LSH: 'lsh',
    BPF_ALU|BPF_RSH: 'rsh',
    BPF_ALU|BPF_NEG: 'neg',
    BPF_ALU|BPF_MOD: 'mod',
    BPF_ALU|BPF_XOR: 'xor',

    # jmp == ja
    BPF_JMP|BPF_JA: 'jmp',
    BPF_JMP|BPF_JEQ: 'jeq',
    BPF_JMP|BPF_JGT: 'jgt',
    BPF_JMP|BPF_JGE: 'jge',
    BPF_JMP|BPF_JSET: 'jset',

    BPF_RET: 'ret',

    BPF_MISC|BPF_TAX: 'tax',
    BPF_MISC|BPF_TXA: 'txa',
}

BinOps = {
    BPF_ADD: '+',
    BPF_SUB: '-',
    BPF_MUL: '*',
    BPF_DIV: '/',
    BPF_OR: '|',
    BPF_AND: '&',
    BPF_LSH: '<<',
    BPF_RSH: '>>',
    BPF_MOD: '%',
    BPF_XOR: '^',
}


def u16(data):
    return unpack('<H', data)[0]

def cast_u32(x):
    return c_uint32(x).value


class Bug(Exception):
    '''Expose a bug (usually an unhandled case)'''
    pass


class Instr(object):
    '''Abstract instruction representation'''

    def __init__(self, opcode, jt, jf, k):
        self.opcode = opcode
        self.jt = jt
        self.jf = jf
        self.k = k

    @property
    def class_(self): return BPF_CLASS(self.opcode)

    @property
    def type(self): return BPF_CLASS(self.opcode)

    @property
    def size(self): return BPF_SIZE(self.opcode)
    
    @property
    def mode(self): return BPF_MODE(self.opcode)
    
    @property
    def op(self): return BPF_OP(self.opcode)
    
    @property
    def src(self): return BPF_SRC(self.opcode)

    @property
    def rval(self): return BPF_RVAL(self.opcode)

    @property
    def miscop(self): return BPF_MISCOP(self.opcode)

    @classmethod
    def from_bytes(cls, bts):
        '''Decode an instruction from head of bts, if possible'''
        if len(bts) >= 8:
            opcode, jt, jf, k = unpack('<HBBI', bts[:8])
            instr = cls(opcode, jt, jf, k)
            return instr
        else:
            return None

    def asm(self):
        '''Assemble this instruction into BPF bytecode'''
        return pack('<HBBI', self.opcode, self.jt, self.jf, self.k)

    def disasm(self, pc):
        '''Convert instruction into disassembly listing'''
        disasm = ''
        
        # LOAD/STORE
        if self.type in [BPF_LD, BPF_LDX, BPF_ST, BPF_STX]:
            disasm += Mnemonics[self.type|self.size]
            val = {
                BPF_IMM: '#{:#x}'.format(self.k),
                BPF_ABS: '[{:#x}]'.format(self.k),
                BPF_IND: '[x + {:#x}]'.format(self.k),
                BPF_MEM: 'M[{:d}]'.format(self.k),
                BPF_MSH: '4*([{:#x}]&0xf)'.format(self.k),
                BPF_LEN: 'len(pkt)',
            }[self.mode]
            disasm += ' {}'.format(val)

        # ALU
        elif self.type in [BPF_ALU]:
            disasm += Mnemonics[self.type|self.op]
            disasm += ' '
            rhs = {
                BPF_K: '#{:#}'.format(self.k),
                BPF_X: 'x',
            }[self.src]
            disasm += rhs

        # JUMPS
        elif self.type in [BPF_JMP]:
            disasm += Mnemonics[self.type|self.op]
            disasm += ' '
            rhs = {
                BPF_K: '#{:#}'.format(self.k),
                BPF_X: 'x',
            }[self.src]
            disasm += rhs

            jtl = self.k if self.op == BPF_JA else self.jt
            jt = pc + 1 + jtl
            jf = pc + 1 + self.jf

            disasm += ', {:04d}'.format(jt)
            # only include false branch if it's not fallthrough
            if jf > pc + 1:
                disasm += ', {:04d}'.format(jf)
            
        # RETURN
        elif self.type in [BPF_RET]:
            disasm += Mnemonics[self.type]
            disasm += ' '
            disasm += {
                BPF_K: '0x{:08x}'.format(self.k),
                BPF_A: 'A',
                BPF_X: 'X',
            }[self.rval]
        
        # MISC
        elif self.type in [BPF_MISC]:
            disasm += Mnemonics[self.type|self.miscop]
        
        else:
            raise Bug('Non-exhaustive class switch: Did not cover {:#x}'.format(self.type))
    
        return disasm

    def comment(self, pc):
        '''Get a comment for this instruction'''
        # LOAD/STORE
        if self.type in [BPF_LD, BPF_LDX]:
            comment = '{} = {}{}'.format(
                { BPF_LD: 'A', BPF_LDX: 'X' }[self.type],
                { BPF_B: '(byte)', BPF_H: '(word)', BPF_W: '' }[self.size],
                { 
                    BPF_IMM: '{:#x}'.format(self.k),
                    BPF_ABS: 'pkt[{:#x}]'.format(self.k),
                    BPF_IND: 'pkt[X + {:#x}]'.format(self.k),
                    BPF_MEM: 'M[{:d}]'.format(self.k),
                    BPF_LEN: 'len(pkt)',
                    BPF_MSH: '4*(pkt[{:#x}] & 0xf)'.format(self.k),
                }[self.mode]
            )

        elif self.type in [BPF_ST, BPF_STX]:
            comment = 'M[{:d}] = (dword) {}'.format(
                self.k, { BPF_ST: 'A', BPF_STX: 'X' }[self.type]
            )
        
        # ALU
        elif self.type in [BPF_ALU]:
            rhs = {
                BPF_K: '#{:#}'.format(self.k),
                BPF_X: 'X',
            }[self.src]
            if self.op == BPF_NEG:
                comment = '!A'
            else:
                comment = 'A {}= {}'.format(BinOps[self.op], rhs)

        # JUMPS
        elif self.type in [BPF_JMP]:
            rhs = {
                BPF_K: '#{:#}'.format(self.k),
                BPF_X: 'X',
            }[self.src]

            jtl = self.k if self.op == BPF_JA else self.jt
            jt = pc + 1 + jtl
            jf = pc + 1 + self.jf

            # add human-readable comment of the condition
            cmpop = {
                BPF_JEQ: '==',
                BPF_JGT: '>',
                BPF_JGE: '>=',
                BPF_JSET: '&',
            }.get(self.op)
            if cmpop is not None:
                comment = '(A {} {}) ? {:04d} : {:04d}'.format(
                    cmpop, rhs, jt, jf)
            else:
                comment = 'goto {:04d}'.format(jt)
            
        # RETURN
        elif self.type in [BPF_RET]:
            comment = ''

        # MISC
        elif self.type in [BPF_MISC]:
            comment = {
                BPF_TAX: 'X = A',
                BPF_TXA: 'A = X'
            }[self.miscop]
        
        else:
            raise Bug('Non-exhaustive class switch: Did not cover {:#x}'.format(self.type))
    
        return comment

    def hexdump(self):
        '''Get a hexdump-like view of the instruction'''
        return '0x{:02x} 0x{:02x} 0x{:02x} 0x{:08x}'.format(
            self.opcode, self.jt, self.jf, self.k)

##
## Emulation types
##
class VMError(Exception):
    '''VM terminated due to an error, e.g. invalid offset deference'''
    pass

class Content(object):
    '''
    Abstract register/memory content representation. Given a known data blob,
    A/X and M[] are defined by some 32-bit value. 
    
    Can one of:

     * An integer (e.g. 'ld #42' means that A = 42)
     * Load of an offset into the data (e.g. 'ldh [0]' means that A contains the
     lower 16-bit of the word starting offset 0 into data)
     * The result of an arithmetic computation (e.g. 'and 0x7f' means that 
     A = <previous value of A> & 0x7f)
    
    'eval' property contains a lambda expression that takes
    the data as argument and evaluates the content into a 
    concrete value.
    '''
    pass

class Int(Content):
    '''A constant 32-bit value that is independent of data'''
    def __init__(self, val):
        self.val = val
    
    @property
    def eval(self):
        return lambda _: self.val

    def __str__(self):
        return str(self.val)


class Offset(Content):
    '''Location contains whatever is at a known offset into data'''
    def __init__(self, off, size):
        self.off = off
        self.size = size

    @property
    def eval(self):
        fmt = '<' + { BPF_B: 'B', BPF_H: 'H', BPF_W: 'I' }[self.size]
        return lambda data: unpack(fmt, data[self.off:self.off+self.size])[0]

    def __str__(self):
        sz = { BPF_B: '(byte)', BPF_H: '(word)', BPF_W: '' }[self.size]
        return '{}pkt[{:#x}]'.format(sz, self.off)


class Alu(Content):
    '''Value can be derived by an ALU computation from an initial data blob'''
    def __init__(self, curA, op, k):
        self.op1 = curA
        self.op2 = k
        self.op = op
    
    @property
    def eval(self):
        return {
            BPF_ADD: lambda data: cast_u32(self.op1.eval(data) + self.op2.eval(data)),
            BPF_SUB: lambda data: cast_u32(self.op1.eval(data) - self.op2.eval(data)),
            BPF_MUL: lambda data: cast_u32(self.op1.eval(data) * self.op2.eval(data)),
            BPF_DIV: lambda data: cast_u32(self.op1.eval(data) / self.op2.eval(data)),
            BPF_OR : lambda data: cast_u32(self.op1.eval(data) | self.op2.eval(data)),
            BPF_AND: lambda data: cast_u32(self.op1.eval(data) & self.op2.eval(data)),
            BPF_LSH: lambda data: cast_u32(self.op1.eval(data) << self.op2.eval(data)),
            BPF_RSH: lambda data: cast_u32(self.op1.eval(data) >> self.op2.eval(data)),
            BPF_MOD: lambda data: cast_u32(self.op1.eval(data) % self.op2.eval(data)),
            BPF_XOR: lambda data: cast_u32(self.op1.eval(data) ^ self.op2.eval(data)),
            # TODO Confirm semantics
            BPF_NEG: lambda data: ~cast_u32(self.op1.eval(data)),
        }[self.op]
    
    def __str__(self):
        if self.op == BPF_NEG:
            return '!A'
        else:
            return 'A {:s}= ({:s})'.format(BinOps[self.op], self.op2)


##
## Seccomp stuff
##

class SeccompData(object):
    nr = 0
    arch = 4
    instruction_pointer = 8
    args = 16
    _sizeof = struct.calcsize('<IIQ' + 'Q'*6)


class SeccompUnknown(Content): pass
class SeccompInt(Int): pass
class SeccompAlu(Alu): pass
class SeccompOffset(Offset, SeccompData):
    def __str__(self):
        sz = { BPF_B: '(byte)', BPF_H: '(word)', BPF_W: '' }[self.size]
        if self.off == self.nr:
            return '{}data.nr'.format(sz)
        elif self.off == self.arch:
            return '{}data.arch'.format(sz)
        elif self.off == self.instruction_pointer:
            return '{}data.instruction_pointer'.format(sz)
        elif self.off % 8 == 0 and self.off < self._sizeof:
            arg_no = (self.off - 16) / 8
            return '{}data.args[{:d}]'.format(sz, arg_no)
        elif self.off >= self._sizeof:
            raise VMError('invalid data offset: {:#x}'.format(self.off))
        else:
            return '{}[{:#x}]'.format(sz, self.off)


class SeccompABI(object):
    '''Constants for a particular Seccomp ABI'''

    # return values
    SECCOMP_RET_KILL    = 0x00000000 # /* kill the task immediately */
    SECCOMP_RET_TRAP    = 0x00030000 # /* disallow and force a SIGSYS */
    SECCOMP_RET_ERRNO   = 0x00050000 # /* returns an errno */
    SECCOMP_RET_TRACE   = 0x7ff00000 # /* pass to a tracer or disallow */
    SECCOMP_RET_LOG     = 0x7ffc0000 # /* allow after logging */
    SECCOMP_RET_ALLOW   = 0x7fff0000 # /* allow */

    SECCOMP_RET_ACTION  = 0x7fff0000 # bitmask for return action
    SECCOMP_RET_DATA    = 0x0000ffff # bitmask for data returned

    def __init__(self, abi):
        if abi == 'i386':
            self.syscalls = self._load_syscall_defs(arch_i386)
        elif abi == 'x86_64':
            self.syscalls = self._load_syscall_defs(arch_x86_64)
        elif abi == 'x32':
            self.syscalls = self._load_syscall_defs(arch_x32)
        else:
            raise ValueError('Unknown ABI: {}'.format(abi))
        
        self.audit_arch = { v: k for k, v in generic.items() if k.startswith('AUDIT_ARCH') }
        self.syscalls[generic['__X32_SYSCALL_BIT']] = '__X32_SYSCALL_BIT'
    
    def _load_syscall_defs(self, d):
        return { num: k.lstrip('__NR_') for k, num in d.items() }

    def stringify_syscall(self, no):
        return self.syscalls.get(no, 'syscall({})'.format(no))

    def stringify_audit(self, val):
        return self.audit_arch.get(val, '{:#x}'.format(val))

    def stringify_retval(self, val):
        if not isinstance(val, int):
            return str(val)
        ret_data = val & self.SECCOMP_RET_DATA
        actions = {
            self.SECCOMP_RET_KILL: 'KILL',
            self.SECCOMP_RET_TRAP: 'TRAP',
            self.SECCOMP_RET_ERRNO: 'ERRNO({})'.format(ret_data),
            self.SECCOMP_RET_TRACE: 'TRACE',
            self.SECCOMP_RET_LOG: 'LOG',
            self.SECCOMP_RET_ALLOW: 'ALLOW',
        }
        if val & self.SECCOMP_RET_ACTION in actions:
            return actions[val & self.SECCOMP_RET_ACTION]
        else:
            return 'KILL'   # See seccomp(2)



class SeccompState(object):
    '''
    Emulation of seccomp BPF programs. Supports both abstract and concrete
    emulation (i.e. without or with a specific seccomp_data value).

    The starting state of the VM is defined mostly by the seccomp_data struct:

    struct seccomp_data {
        int   nr;                   /* System call number */
        __u32 arch;                 /* AUDIT_ARCH_* value
                                        (see <linux/audit.h>) */
        __u64 instruction_pointer;  /* CPU instruction pointer */
        __u64 args[6];              /* Up to 6 system call arguments */
    };

    If :param:seccomp_data is None, "execution" only considers abstract
    values in the form of references etc. No jumps are evaluated nor 
    executed. This mode is useful to get a disassembly listing.

    Possible return values (seccomp(2)):

       SECCOMP_RET_KILL_PROCESS (since Linux 4.14)
       SECCOMP_RET_KILL_THREAD (or SECCOMP_RET_KILL)
       SECCOMP_RET_TRAP
       SECCOMP_RET_ERRNO
       SECCOMP_RET_TRACE
       SECCOMP_RET_LOG (since Linux 4.14)
       SECCOMP_RET_ALLOW

    "If an action value other than one of the above is specified, then the
    filter action is treated as either SECCOMP_RET_KILL_PROCESS (since
    Linux 4.14) or SECCOMP_RET_KILL_THREAD (in Linux 4.13 and earlier)."

    TODO: Full symbolic execution with arbitrary expressions for e.g.
    arithmetic manipulations of known values
    '''
    # architecture of calling process, e.g. for decoding syscall numbers
    ARCH_UNK = 0
    ARCH_I386 = 1
    ARCH_X86_64 = 2
    ARCH_X32 = 3

    VM_NOT_STARTED = -1

    SIZEOF_DATA = 0x40

    def __init__(self, seccomp_data=None, arch=None):
        self.arch = arch or SeccompState.ARCH_UNK
        # Next instruction to fetch
        self.cur_pc = 0
        # Referenced when printing disassembly listings _after_ update of state
        self.prev_pc = self.VM_NOT_STARTED
        self.data = seccomp_data

        # Instantiate with abstract values
        self.A = SeccompInt(0)
        self.X = SeccompInt(0)
        self.M = [SeccompInt(0)]*16
        # VM has stopped (and returned) when retval or error are non-None
        self.retval = None
        self.error = None

    def eval(self, var):
        if self.data != None:
            return var.eval(self.data)
        else:
            return var
    

class SimpleSeccompState(object):

    def __init__(self, abi):
        self.abi = SeccompABI(abi)
        self.pc = 0
        self.A = SeccompUnknown()
        self.X = SeccompUnknown()
        self.M = [SeccompUnknown()]*16


class SeccompInstr(Instr):

    def disasm(self, state):
        '''
        Convert instruction into a pseudo-disassembly statement. Updates state with
        effect of instruction on type of registers
        '''
        pc = state.pc

        # LOAD/STORE
        if self.type in [BPF_LD, BPF_LDX]:
            dest = { BPF_LD: 'A', BPF_LDX: 'X' }[self.type]
            if self.mode == BPF_ABS:
                val = SeccompOffset(self.k, self.size)
                setattr(state, dest, val)
            elif self.mode == BPF_MEM:
                val = 'M[{:d}]'.format(self.k)
                setattr(state, dest, state.M[self.k])
            else:
                val = {
                    # Offset into seccomp_data struct
                    BPF_IND: '[X + {:#x}]'.format(self.k),
                    BPF_IMM: '#{:#x}'.format(self.k),
                    BPF_LEN: '#{:#x}'.format(SeccompState.SIZEOF_DATA),
                    BPF_MSH: '4*([{:#x}]&0xf)'.format(self.k),
                }[self.mode]
                setattr(state, dest, SeccompUnknown())
            disasm = '{} = {}'.format(dest, val)

        elif self.type in [BPF_ST, BPF_STX]:
            src = { BPF_ST: 'A', BPF_STX: 'X' }[self.type]
            disasm = 'M[{:d}] = {}'.format(self.k, src)
            state.M[self.k] = getattr(state, src)

        # ALU
        elif self.type in [BPF_ALU]:
            rhs = {
                BPF_K: '#{:#}'.format(self.k),
                BPF_X: 'X',
            }[self.src]
            if self.op == BPF_NEG:
                disasm = '!A'
            else:
                disasm = 'A {}= {}'.format(BinOps[self.op], rhs)
            state.A = SeccompUnknown()

        # JUMPS
        elif self.type in [BPF_JMP]:
            if self.src == BPF_K:
                if isinstance(state.A, SeccompOffset) and state.A.off == SeccompData.nr:
                    rhs = state.abi.stringify_syscall(self.k)
                else:
                    rhs = '{:#x}'.format(self.k)
            elif self.src == BPF_X:
                rhs = 'X'

            jtl = self.k if self.op == BPF_JA else self.jt
            jt = pc + 1 + jtl
            jf = pc + 1 + self.jf

            cmpop = {
                BPF_JEQ: '==',
                BPF_JGT: '>',
                BPF_JGE: '>=',
                BPF_JSET: '&',
            }.get(self.op)
            if cmpop is not None:
                disasm = '(A {} {}) ? {:04d}'.format(cmpop, rhs, jt)
                if jf > pc + 1:
                    disasm += ' : {:04d}'.format(jf)
            else:
                disasm = 'goto {:04d}'.format(jt)
            
        # RETURN
        elif self.type in [BPF_RET]:
            val = state.abi.stringify_retval({
                BPF_K: self.k,
                BPF_A: state.A,
                BPF_X: state.X,
            }[self.rval])
            disasm = 'return {}'.format(val)
        
        # MISC
        elif self.type in [BPF_MISC]:
            disasm, state.A, state.X = {
                BPF_TAX: ('X = A', state.A, state.A),
                BPF_TXA: ('A = X', state.X, state.X),
            }
        
        else:
            raise Bug('Non-exhaustive class switch: BPF_CLASS: {:#x}'.format(self.type))
    
        state.pc += 1
        return disasm
