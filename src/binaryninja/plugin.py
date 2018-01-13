from binaryninja import *
from bpftools.bpf import *
from functools import partial


_BN_PseudoPacketAddr = 0x400000
_BN_PseudoLenAddr = 0x400000
# BinaryNinja work-around: pointer to data does not handle offset 0 very well
_BN_PseudoDataAddr = 0x400010+0x4
_BN_PseudoMemAddr = 0x500000


class BN_BPFArch(Architecture):
    name = 'bpf'
    # PC is a short
    address_size = 2
    max_instr_length = INSTR_SIZE
    default_int_size = 4

    regs = {
        'A': RegisterInfo('A', 4),
        'X': RegisterInfo('X', 4),
        # fake stack pointer
        'sp': RegisterInfo('sp', 4),
        # fake return value register
        'retval': RegisterInfo('retval', 4),
    }
    stack_pointer = 'sp'

    def __init__(self, *args, **kwargs):
        super(BN_BPFArch, self).__init__(*args, **kwargs)

        def _create_token(token_type, *args):
            return InstructionTextToken(token_type, *args)

        TokType = InstructionTextTokenType
        self.Txt = partial(_create_token, TokType.TextToken)
        self.Mnemonic = partial(_create_token, TokType.InstructionToken)
        self.Sep = partial(_create_token, TokType.OperandSeparatorToken)
        self.Reg = partial(_create_token, TokType.RegisterToken)
        self.Int = lambda x: InstructionTextToken(TokType.IntegerToken, hex(x), x)
        self.Addr = lambda x: InstructionTextToken(TokType.PossibleAddressToken, hex(x), x)
        self.Float = partial(_create_token, TokType.FloatingPointToken)
        self.LBracket = _create_token(TokType.BeginMemoryOperandToken, '[')
        self.RBracket = _create_token(TokType.EndMemoryOperandToken, ']')

        self.space = self.Sep(' ')
        self.comma = self.Sep(', ')
        self.mem = lambda inner: [self.LBracket] + inner + [self.RBracket]


    def _tokenize(self, pc, instr):
        T = self
        tokens = []

        # LOAD/STORE
        if instr.type in [BPF_LD, BPF_LDX, BPF_ST, BPF_STX]:
            tokens += [
                T.Mnemonic(Mnemonics[instr.type|instr.size]),
                T.space,
            ] + {
                BPF_IMM: [T.Int(instr.k)],

                BPF_ABS: T.mem([T.Addr(_BN_PseudoDataAddr + instr.k)]),
                BPF_IND: T.mem([T.Reg('X'), T.Sep('+'), T.Int(instr.k)]),

                # TODO implement as typed pseudo datavar?
                BPF_MEM: [T.Txt('M')] + T.mem([T.Int(instr.k)]),

                BPF_LEN: T.mem([T.Addr(_BN_PseudoLenAddr)]),
                BPF_MSH: [
                    T.Int(4),
                    T.Sep('*'),
                    T.Txt('(')
                ] + T.mem([T.Addr(_BN_PseudoDataAddr + instr.k)]) + [
                    T.Txt('&'), T.Int(0xf), T.Txt(')')
                ]
            }[instr.mode]

        # ALU
        elif instr.type in [BPF_ALU]:
            tokens += [
                T.Mnemonic(Mnemonics[instr.type|instr.op]),
                T.space, {
                    BPF_K: T.Int(instr.k),
                    BPF_X: T.Reg('X'),
                }[instr.src]
            ]

        # JUMPS
        elif instr.type in [BPF_JMP]:
            # jump target is usually jt, unless unconditional jmp
            jtl = instr.k if instr.op == BPF_JA else instr.jt
            jt = T.Addr((pc + 1 + jtl) * INSTR_SIZE)
            jf = T.Addr((pc + 1 + instr.jf) * INSTR_SIZE)
            tokens += [
                T.Mnemonic(Mnemonics[instr.type|instr.op]),
                T.space,
                {
                    BPF_K: T.Int(instr.k),
                    BPF_X: T.Reg('X'),
                }[instr.src],
                T.space,
                jt,
                T.space,
                jf
            ]
            
        # RETURN
        elif instr.type in [BPF_RET]:
            tokens += [
                T.Mnemonic(Mnemonics[instr.type]),
                T.space, {
                    BPF_K: T.Int(instr.k),
                    BPF_A: T.Reg('A'),
                    BPF_X: T.Reg('X'),
                }[instr.rval]
            ]
        
        # MISC
        elif instr.type in [BPF_MISC]:
            tokens += [T.Mnemonic(Mnemonics[instr.type|instr.miscop])]
        
        else:
            raise Bug('Non-exhaustive class switch: BPF_CLASS {:#x}'.format(instr.type))

        return tokens

    def _get_jump_label(self, il, pc):
        addr = pc * INSTR_SIZE
        lbl = il.get_label_for_address(self, addr)
        if lbl is None:
            lbl = LowLevelILLabel()
            il.mark_label(lbl)
        return lbl

    def _lift(self, il, pc, instr):
        sz = 4
        regA = il.reg(sz, 'A')
        regX = il.reg(sz, 'X')
        constK = il.const(sz, instr.k)

        if instr.type|instr.mode in [BPF_LD|BPF_ABS, BPF_LDX|BPF_ABS]:
            sz = { BPF_B: 1, BPF_H: 2, BPF_W: 4 }[instr.size]
            load_addr = il.const_pointer(sz, _BN_PseudoDataAddr + instr.k)
            e = il.set_reg(
                sz, 
                { BPF_LD: 'A', BPF_LDX: 'X' }[instr.type],
                il.load(sz, load_addr)
            )
            il.append(e)
        
        elif instr.type in [BPF_LD, BPF_LDX]:
            # TODO Handle other addressing modes
            il.append(il.unimplemented())
        
        elif instr.type in [BPF_ST, BPF_STX]:
            store_addr = il.const_pointer(sz, _BN_PseudoMemAddr + instr.k * sz)
            e = il.store(
                sz,
                store_addr,
                { BPF_ST: regA, BPF_STX: regX }[instr.type],
            )
            il.append(e)
        
        elif instr.type in [BPF_ALU]:
            rhs = { BPF_K: constK, BPF_X: regX }[instr.src]
            args = (sz, regA) if instr.op == BPF_NEG else (sz, regA, rhs)
            e = il.set_reg(sz, 'A', {
                BPF_ADD: il.add,
                BPF_SUB: il.sub,
                BPF_MUL: il.mult,
                BPF_DIV: il.div_unsigned,
                BPF_OR: il.or_expr,
                BPF_AND: il.and_expr,
                BPF_LSH: il.shift_left,
                BPF_RSH: il.logical_shift_right,
                BPF_MOD: il.mod_unsigned,
                BPF_XOR: il.xor_expr,
                BPF_NEG: il.not_expr
            }[instr.op](*args))
            il.append(e)

        elif instr.type in [BPF_JMP]:
            if instr.op == BPF_JA:
                jmp = pc + 1 + instr.k
                lbl = self._get_jump_label(jmp)
                e = il.goto(lbl)
                il.append(e)

            else:
                jt = pc + 1 + instr.jt
                jf = pc + 1 + instr.jf
                true_lbl = self._get_jump_label(il, jt)
                false_lbl = self._get_jump_label(il, jf)
                cond = {
                    BPF_JEQ: il.compare_equal(sz, regA, constK),
                    BPF_JGT: il.compare_unsigned_greater_than(sz, regA, constK),
                    BPF_JGE: il.compare_unsigned_greater_equal(sz, regA, constK),
                    BPF_JSET: il.compare_not_equal(sz, il.and_expr(sz, regA, constK), il.const(sz, 0)),
                }[instr.op]
                e = il.if_expr(cond, true_lbl, false_lbl)
                il.append(e)

        elif instr.type in [BPF_RET]:
            il.append(il.ret({
                BPF_K: il.const(sz, instr.k),
                BPF_X: regX,
                BPF_A: regA,
            }[instr.rval]))
        
        elif instr.type in [BPF_MISC]:
            il.append(il.set_reg(
                4, 
                { BPF_TAX: 'A', BPF_TXA: 'X' }[self.op],
                il.reg(4, { BPF_TAX: 'X', BPF_TXA: 'A' }[self.op]),
            ))

        else:
            il.append(il.unimplemented())

    def perform_always_branch(self, data, addr):
        src_instr = Instr.from_bytes(data)
        pc = addr / INSTR_SIZE
        if src_instr.type != BPF_JMP:
            return None, 'Not a jump instruction'

        target_pc = pc + 1 + (src_instr.k if src_instr.op == BPF_JA else src_instr.jt)
        new_instr = Instr(BPF_JMP|BPF_JA, 0, 0, target_pc)
        return new_instr.asm(), ''

    def perform_get_instruction_info(self, data, addr):
        instr = Instr.from_bytes(data)
        pc = addr / INSTR_SIZE

        info = InstructionInfo()
        info.length = INSTR_SIZE

        # Branching
        if instr.type == BPF_RET:
            info.add_branch(BranchType.FunctionReturn)

        elif instr.type|instr.op == BPF_JMP|BPF_JA:
            jmp = pc + 1 + instr.k
            info.add_branch(BranchType.UnconditionalBranch, jmp * 8)

        elif instr.type == BPF_JMP:
            jt = pc + 1 + instr.jt
            jf = pc + 1 + instr.jf
            info.add_branch(BranchType.TrueBranch, jt * INSTR_SIZE)
            info.add_branch(BranchType.FalseBranch, jf * INSTR_SIZE)

        return info

    def perform_get_instruction_text(self, data, addr):
        instr = Instr.from_bytes(data)
        pc = addr / INSTR_SIZE
        tokens = self._tokenize(pc, instr)
        return tokens, INSTR_SIZE

    def perform_get_instruction_low_level_il(self, data, addr, il):
        instr = Instr.from_bytes(data)
        pc = addr / INSTR_SIZE
        self._lift(il, pc, instr)
        return INSTR_SIZE

    def perform_convert_to_nop(self, data, addr):
        if len(data) != 8:
            return None
        # meh
        nop_instr = Instr(BPF_ALU|BPF_AND|BPF_K, 0, 0, 0xffffffff)
        return nop_instr.asm()


class BN_BPFPlatform(Platform):
    name = 'bpf-vm'

    def __init__(self, *args, **kwargs):
        super(BN_BPFPlatform, self).__init__(*args, **kwargs)
        self.register('bpf-vm')


class BN_BPFView(BinaryView):
    name = 'BPF'
    long_name = 'BPF Program'

    def __init__(self, data):
        super(BN_BPFView, self).__init__(parent_view=data, file_metadata=data.file)

    @classmethod
    def is_valid_for_data(cls, data):
        return len(data[2:]) % 8 == 0

    def _init_bpf(self):
        self.arch = Architecture['bpf']
        self.platform = BN_BPFPlatform(self.arch)

        load_addr = 0x0
        self.entry_addr = load_addr
        self.add_entry_point(load_addr)

        prog_len = u16(self.parent_view.read(0, 2))

        self.add_auto_segment(load_addr, prog_len, 2, prog_len, 
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)

        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.entry_addr, 'program'))
        self.prog = self.get_function_at(load_addr)

        # for "pkt" references
        self.add_auto_segment(_BN_PseudoPacketAddr, 0x1000, 0, 0, SegmentFlag.SegmentReadable)

        # available for BPF_LEN references
        data_type, name = self.parse_type_string('uint32_t pkt_len;')
        self.define_data_var(_BN_PseudoLenAddr, data_type)
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, _BN_PseudoLenAddr, 'pkt_len'))

        # For M[] references
        self.add_auto_segment(_BN_PseudoMemAddr, 4*16, 0, 0, 
            SegmentFlag.SegmentReadable|SegmentFlag.SegmentWritable)
        data_type, name = self.parse_type_string('uint32_t M[16];')
        self.define_data_var(_BN_PseudoMemAddr, data_type)
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, _BN_PseudoMemAddr, 'M'))

        self.arch.set_view_type_constant('BPF', 'SYS_execve', 0x3b)

        # TODO Add comments from instr.comment()

        return True

    def init(self):
        return self._init_bpf()

    def perform_is_valid_offset(self, addr):
        return 0x0 <= addr and addr <= 0xffff

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr


# class BN_SeccompPlatform(Platform):
#     name = 'bpf-vm'

#     def __init__(self, *args, **kwargs):
#         super(BN_BPFPlatform, self).__init__(*args, **kwargs)
#         self.register('bpf-vm')


class BN_SeccompView(BN_BPFView):
    name = 'Seccomp'
    long_name = 'Seccomp Filter Program'

    def _init_seccomp(self):
        '''Additional symbols etc when handling a Seccomp BPF program'''
        # References to seccomp_data
        data_type, name = self.parse_type_string('struct seccomp_data data;')
        self.define_data_var(_BN_PseudoDataAddr-0x4, data_type)
        self.define_auto_symbol(Symbol(SymbolType.DataSymbol, _BN_PseudoDataAddr-0x4, 'data'))

        # Names for return values
        # ret_base_addr = _BN_PseudoRetAddr
        # self.add_auto_section('ret1', ret_base_addr, 0x60000)
        # self.add_auto_section('ret2', ret_base_addr+0x7ff00000, 0xfffff)

        # self.define_auto_symbol(Symbol(SymbolType.DataSymbol, ret_base_addr+SeccompState.SECCOMP_RET_KILL, 'KILL'))
        # self.define_auto_symbol(Symbol(SymbolType.DataSymbol, ret_base_addr+SeccompState.SECCOMP_RET_TRAP, 'TRAP'))
        # for i in range(20):
        #     self.define_auto_symbol(Symbol(SymbolType.DataSymbol, ret_base_addr+SeccompState.SECCOMP_RET_ERRNO+i, 'ERRNO({})'.format(i)))
        # self.define_auto_symbol(Symbol(SymbolType.DataSymbol, ret_base_addr+SeccompState.SECCOMP_RET_TRACE, 'TRACE'))
        # self.define_auto_symbol(Symbol(SymbolType.DataSymbol, ret_base_addr+SeccompState.SECCOMP_RET_LOG, 'LOG'))
        # self.define_auto_symbol(Symbol(SymbolType.DataSymbol, ret_base_addr+SeccompState.SECCOMP_RET_ALLOW, 'ALLOW'))

    def init(self):
        return self._init_bpf() and self._init_seccomp()


BN_BPFArch.register()
BN_BPFView.register()
BN_SeccompView.register()
