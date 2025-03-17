import angr
import os

BINARY_PATH = './adc_fft_dma'
LOG_FILE = 'log.txt'

def get_branch_type(insn):
    # Common AArch64 branch instructions
    if insn.mnemonic in ['b', 'bx', 'br']: 
        return 'unconditional'
    elif insn.mnemonic in ['bl', 'blx', 'blr']:
        return 'call'
    elif insn.mnemonic in ['cbz', 'cbnz']:
        return 'conditional (register)'
    elif insn.mnemonic in ['tbz', 'tbnz']:
        return 'conditional (test bit)'
    elif insn.mnemonic == 'ret':
        return 'return'
    else:
        return 'unknown'

def generate_cfg(binary_path):
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    with open(LOG_FILE, 'w') as log:
        for node in cfg.graph.nodes():
            # Get the basic block at this node's address
            block = proj.factory.block(node.addr)

            for insn in block.capstone.insns:
                branch_type = get_branch_type(insn)
                if branch_type != 'unknown':
                    # Find the destination if available in the CFG
                    for succ in cfg.graph.successors(node):
                        src = hex(node.addr)
                        dest = hex(succ.addr)
                        log.write(f"{src} -> {dest} ({branch_type})\n")
                        print(f"{src} -> {dest} ({branch_type})")

if __name__ == "__main__":
    if os.path.exists(BINARY_PATH):
        generate_cfg(BINARY_PATH)
        print(f"CFG data written to '{LOG_FILE}'")
    else:
        print(f"Binary '{BINARY_PATH}' not found!")
