from bpftools.bpf import *


def transpile_to_x86_64_elf(bpf):
    '''
    Transpile a BPF program into an x86_64 ELF that is 
    semantically equivalent to the BPF program
    '''
    
    '''
    Labels:
    All instructions get a instr_0 label

    Return value:
    Value goes in eax
    jmp to global "return" value
    
    Template:
    * get "packet" from argv/stdin, store in stack buffer pointed to by ebp
    * make M[16] on stack, pointed to by esp
    * xor eax (A), ebx (B) 

    * transpiled instructions

    * return:
     - make retval available
     - exit() syscall
    '''
    pass

