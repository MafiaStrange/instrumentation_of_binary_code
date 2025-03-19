#!/usr/bin/env python3
#
# ARMv7 bare metal binary instrumentation tool
#
# Copyright (c) 2016 Aalto University
#
import argparse
import binascii
import configparser
import logging
import math
import mmap
import os.path
import struct
import sys
from argparse import Namespace
from bitarray import bitarray
from capstone import *
from enum import Enum
from datetime import datetime

CONFIG_DEFAULT_PATHNAME = './hookit.cfg.sample'
CONFIG_SECTION_CODE_ADDRESSES = 'code-addresses'
CONFIG_SECTION_HOOK_ADDRESSES = 'hook-addresses'

DEFAULT_BTBL_PATHNAME = 'btbl.c'
DEFAULT_LTBL_PATHNAME = 'ltbl.c'

CONFIG_DEFAULTS = {
        'load_address'   : '0x0000',
        'text_start'     : "",
        'text_end'       : "",
        'omit_addresses' : "",
        'hook_b'         : "",
        'hook_bl'        : "",
        'hook_br'        : "",
        'hook_blr'       : ""
}

class CFS(Enum):
    b         = 1
    bl        = 2
    br        = 3
    blr       = 4

def new_cfs(cfs_type, cfs_instr, cfs_src, cfs_dst):
    return Namespace(
            type = cfs_type,
            instr = cfs_instr,
            src  = cfs_src,
            dst  = cfs_dst,
    )


def read_config(pathname):
    parser = configparser.ConfigParser(defaults=CONFIG_DEFAULTS)  # Use defaults correctly
    parser.read(pathname)

    config = {}

    # Ensure 'DEFAULT' section exists and extract values
    if parser.has_section('DEFAULT') or parser.defaults():
        for key, value in parser['DEFAULT'].items():
            config[key] = value.strip()  # Trim extra spaces

    # Convert values where necessary
    config['load_address'] = config['load_address']
    config['text_start'] = config['text_start'] if config['text_start'] else None
    config['text_end'] = config['text_end'] if config['text_end'] else None

    # Handle omit_addresses as a list of integers
    config['omit_addresses'] = (
        [addr.strip() for addr in config['omit_addresses'].split(',') if addr]
        if config['omit_addresses']
        else []
    )

    return config
    

def main():
    parser = argparse.ArgumentParser(description='ARMv7 Branch Target Rewriting Tool')
    
    # Define arguments
    parser.add_argument('-c', '--config', dest='config', default=None, help='Configuration file')

    args, remaining_args = parser.parse_known_args()

    # Read the config file if provided
    config = {}
    if args.config:
        config = read_config(args.config)

    # Now parse command-line arguments, using config defaults
    parser.add_argument('file', nargs='?', metavar='FILE', help='Binary file to instrument')
    parser.add_argument('-L', '--load-address', dest='load_address', default=config.get('load_address'),
                        help='Load address of binary image')
    parser.add_argument('--text-start', dest='text_start', default=config.get('text_start'),
                        help='Start address of section to instrument')
    parser.add_argument('--text-end', dest='text_end', default=config.get('text_end'),
                        help='End address of section to instrument')
    parser.add_argument('--omit-addresses', dest='omit_addresses', default=config.get('omit_addresses'),
                        help='Comma-separated addresses to omit from instrumentation')
    parser.add_argument('-o', '--outfile', dest='outfile', default=config.get('outfile'),
                        help='Output file for branch table')
    parser.add_argument('--verbose', '-v', action='count', default=int(config.get('verbose', 0)),
                        help='Verbose output (repeat up to three times)')
    
    parser.add_argument('-l', '--little-endian', dest='flags', default=[], action='append_const', const=CS_MODE_LITTLE_ENDIAN,
                        help='disassemble in little endian mode')
    parser.add_argument('-b', '--big-endian', dest='flags', default=[], action='append_const', const=CS_MODE_BIG_ENDIAN,
                        help='disassemble in big endian mode')
    parser.add_argument('--dry-run', '-n', dest='dry_run', action='store_true',
                        help='perform a dry run (do not modify binary)')
    parser.add_argument('--print-cfs-table', dest='print_cfs_table', action='store_true',
                        help='print control flow statement table')
    parser.add_argument('--print-branch-table', dest='print_branch_table', action='store_true',
                        help='')
    parser.add_argument('--print-loop-table', dest='print_loop_table', action='store_true',
                        help='')
    parser.add_argument('--create-branch-table', dest='gen_branch_table', action='store_true',
                        help='')
    parser.add_argument('--create-loop-table', dest='gen_loop_table', action='store_true',
                        help='')
    

    # Save a copy of args before re-parsing
    old_args = vars(args).copy()  # Store original args as a dictionary

    # Parse final arguments
    args = parser.parse_args(remaining_args)

    # Restore values that were in old_args but are missing in new args
    for key, value in old_args.items():
        if getattr(args, key, None) is None:
            setattr(args, key, value)

    for key,value in config.items():
        if getattr(args, key, None) is None:
            setattr(args, key, value)

    if args.verbose is None:
        logging.basicConfig(format='%(message)s',level=logging.ERROR)
    elif args.verbose == 1:
        logging.basicConfig(format='%(message)s',level=logging.WARNING)
    elif args.verbose == 2:
        logging.basicConfig(format='%(message)s',level=logging.INFO)
    elif args.verbose >= 3:
        logging.basicConfig(format='%(message)s',level=logging.DEBUG)

    try:
        config = read_config(args.config if args.config is not None
                else CONFIG_DEFAULT_PATHNAME)
    except configparser.MissingSectionHeaderError as error:
            logging.error(error)
            sys.exit(1)

    def get_req_opt(opt,config):
        args_value = getattr(args, opt, None)
        config_value = config.get(opt, None)

        value = args_value if args_value is not None else config_value
        if value == "":
            raise ValueError(f"Missing required option: {opt}")

        return int(value, 16)  


    def get_csv_opt(opt):
        args_value = getattr(args, opt, None)  # Use default None
        config_value = getattr(config, opt, None)

        if isinstance(args_value, list):
            return args_value  # Already a list, return as-is
        elif isinstance(args_value, str):
            return args_value.split(',')

        if isinstance(config_value, list):
            return config_value  # Already a list, return as-is
        elif isinstance(config_value, str):
            return config_value.split(',')

        return []  # Return empty list if no value found


    opts = Namespace(
            binfile        = args.file,
            outfile        = args.outfile,
            dry_run        = args.dry_run,
            cs_mode_flags  = args.flags,
            load_address   = get_req_opt('load_address',config),
            text_start     = get_req_opt('text_start',config),  
            text_end       = get_req_opt('text_end',config),    
            omit_addresses = [int(i,16) for i in get_csv_opt('omit_addresses')],
            hook_b         = get_req_opt('hook_b',config),    
            hook_bl        = get_req_opt('hook_bl',config),   
            hook_br        = get_req_opt('hook_br',config),
            hook_blr       = get_req_opt('hook_blr',config),   
            print_cfs_table = args.print_cfs_table,
            print_branch_table = args.print_branch_table,
            print_loop_table = args.print_loop_table,
            gen_branch_table = args.gen_branch_table,
            gen_loop_table = args.gen_loop_table,
    )

    logging.debug("load_address         = 0x%08x" % opts.load_address)
    logging.debug("text_start           = 0x%08x" % opts.text_start)
    logging.debug("text_end             = 0x%08x" % opts.text_end)
    logging.debug("omit_addresses       = %s" % ['0x%08x' % i for i in opts.omit_addresses])
    logging.debug("hook_b               = 0x%08x" % opts.hook_b)
    logging.debug("hook_bl              = 0x%08x" % opts.hook_bl)
    logging.debug("hook_br              = 0x%08x" % opts.hook_br)
    logging.debug("hook_blr             = 0x%08x" % opts.hook_blr)

    if not os.path.isfile(args.file):
        sys.exit("%s: file '%s' not found" % (sys.argv[0], args.file))

    control_flow_statements = hookit(opts)

    if opts.print_cfs_table:
        for cfs in control_flow_statements:
            print ("%s,0x%08x,0x%08x" % (hexbytes(cfs.instr), cfs.src, cfs.dst))

    if opts.print_branch_table:
        for cfs in get_branches(control_flow_statements):
            print ("0x%08x,0x%08x" % (cfs.src, cfs.dst))

    if opts.print_loop_table:
        for (entry, exit) in get_loops(control_flow_statements):
            print ("0x%08x,0x%08x" % (entry, exit))

    if opts.gen_branch_table:
        write_branch_table(opts.outfile if opts.outfile != None else DEFAULT_BTBL_PATHNAME,
                get_branches(control_flow_statements))

    if opts.gen_loop_table:
        write_loop_table(opts.outfile if opts.outfile != None else DEFAULT_LTBL_PATHNAME,
                get_loops(control_flow_statements))

def get_branches(control_flow_statements):
     return [c for c in control_flow_statements if c.type == CFS.b or c.type == CFS.bl]

def get_loops(control_flow_statements):
    branches = [c for c in control_flow_statements if (c.type == CFS.b and c.dst < c.src)]
    loop_entries = set([c.dst for c in branches])
    loops = [(entry, 4 + max([b.src for b in branches if b.dst == entry])) for entry in loop_entries]
    return sorted(loops, key=lambda x: x[0])

def hookit(opts):
    control_flow_statements = []

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    with open(opts.binfile, "r+b") as f:
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ | mmap.PROT_WRITE)

        offset = opts.text_start - opts.load_address
        logging.debug("hooking %s from 0x%08x to 0x%08x" % 
                      (opts.binfile, offset, opts.text_end - opts.load_address))

        # Initialize address tracking
        current_address = opts.text_start
        prev_address = -1

        while True:
            # Read the next instruction (4 bytes at a time for AArch64)
            mm.seek(current_address - opts.load_address)
            code = mm.read(4)

            if len(code) < 4:
                # Reached end of mapped region
                break

            # Disassemble a **single instruction**
            instructions = list(md.disasm(code, current_address))

            if len(instructions) == 0:
                # Failed to decode the instruction, log and skip to next address
                logging.warning(f"Invalid instruction at 0x{current_address:08x}, skipping.")
                current_address += 4
                continue

            i = instructions[0]  # We only asked for one instruction

            # Skip duplicate (very unlikely with 4-byte stepping, but for safety)
            if i.address == prev_address:
                current_address += 4
                continue
            else:
                prev_address = i.address

            # Skip addresses explicitly omitted
            if i.address in opts.omit_addresses:
                logging.info("omit at 0x%08x: %-10s\t%s\t%s" %
                             (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))
                current_address += 4
                continue

            # Process instructions
            if i.mnemonic == "b":
                rewrite_branch(mm, control_flow_statements, opts.load_address, i, opts.hook_b, md, opts.dry_run)
            elif i.mnemonic == "bl":
                rewrite_branch_with_link(mm, control_flow_statements, opts.load_address, i, opts.hook_bl, md, opts.dry_run)
            elif i.mnemonic == "br" and len(i.operands) == 1:
                rewrite_branch_register(mm, control_flow_statements, opts.load_address, i, opts.hook_br, md, opts.dry_run)
            elif i.mnemonic == "blr" and len(i.operands) == 1:
                rewrite_branch_link_register(mm, control_flow_statements, opts.load_address, i, opts.hook_blr, md, opts.dry_run)
            else:
                logging.debug("      0x%08x: %-10s\t%s\t%s" %
                              (i.address, hexbytes(i.bytes), i.mnemonic, i.op_str))

            # Stop if we exceed the text section
            if i.address >= opts.text_end:
                break

            # Advance to next instruction (trust Capstone instruction size)
            current_address += i.size

            # Hard stop at file boundary
            if current_address >= opts.text_end or current_address >= opts.load_address + mm.size():
                break

    return control_flow_statements


def rewrite_branch(mm, cfs_table, load_address, i, target, md, dry_run=False):
    word = new_branch_with_link_instruction(i, target)

    j = disasm_single(word, i.address, md)
    
    if j:  # Ensure j is not empty before accessing attributes
        instr = j[0]  # Take the first instruction

        logging.info("b     at 0x%08x: hooking %-10s\t%s\t%s -> %-10s\t%s\t%s" %
                (i.address,
                    hexbytes(i.bytes), i.mnemonic, i.op_str,
                    hexbytes(instr.bytes), instr.mnemonic, instr.op_str))
    else:
        logging.warning("Disassembly failed at 0x%08x: Instruction could not be decoded." % i.address)
        return  # Stop execution to prevent further errors

    cfs_table.append(new_cfs(CFS.b, i.bytes, i.address, get_branch_target(i)))

    if dry_run:
        return

    write_back(mm, i.address - load_address, word)


def rewrite_branch_with_link(mm, cfs_table, load_address, i, target, md, dry_run=False):
    word = new_branch_with_link_instruction(i, target)

    j = disasm_single(word, i.address, md)

    if j:  # Ensure disassembly returned at least one instruction
        instr = j[0]  # Take the first instruction

        logging.info("bl    at 0x%08x: hooking %-10s\t%s\t%s -> %-10s\t%s\t%s" %
                (i.address,
                    hexbytes(i.bytes), i.mnemonic, i.op_str,
                    hexbytes(instr.bytes), instr.mnemonic, instr.op_str))
    else:
        logging.warning("Disassembly failed at 0x%08x: Instruction could not be decoded." % i.address)
        return  # Stop execution to prevent further errors

    cfs_table.append(new_cfs(CFS.bl, i.bytes, i.address, get_branch_target(i)))

    if dry_run:
        return

    write_back(mm, i.address - load_address, word)

def rewrite_branch_register(mm, cfs_table, load_address, i, target, md, dry_run=False):
    word = new_branch_with_link_instruction(i, target)  # This should generate the new `br` instruction to `target`

    j = disasm_single(word, i.address, md)

    if j:
        instr = j[0]
        logging.info("br    at 0x%08x: hooking %-10s\t%s\t%s -> %-10s\t%s\t%s" %
                     (i.address,
                      hexbytes(i.bytes), i.mnemonic, i.op_str,
                      hexbytes(instr.bytes), instr.mnemonic, instr.op_str))
    else:
        logging.warning("Disassembly failed at 0x%08x: Instruction could not be decoded." % i.address)
        return

    cfs_table.append(new_cfs(CFS.br, i.bytes, i.address, None))  # No static target for `br`, it's dynamic.

    if dry_run:
        return

    write_back(mm, i.address - load_address, word)

def rewrite_branch_and_exchange_lr(mm, cfs_table, load_address, i, target, md, dry_run=False):
    word = new_branch_with_link_instruction(i, target)

    j = disasm_single(word, i.address, md)

    if j:  
        instr = j[0]  

        logging.info("bx lr at 0x%08x: hooking %-10s\t%s\t%s -> %-10s\t%s\t%s" %
                (i.address,
                    hexbytes(i.bytes), i.mnemonic, i.op_str,
                    hexbytes(instr.bytes), instr.mnemonic, instr.op_str))
    else:
        logging.warning("Disassembly failed at 0x%08x: Instruction could not be decoded." % i.address)
        return  

    cfs_table.append(new_cfs(CFS.br, i.bytes, 0, 0))

    if dry_run:
        return

    write_back(mm, i.address - load_address, word)

def rewrite_branch_link_register(mm, cfs_table, load_address, i, target, md, dry_run=False):
    word = new_branch_with_link_instruction(i, target)  # This should generate the new `blr` instruction to `target`

    j = disasm_single(word, i.address, md)

    if j:
        instr = j[0]
        logging.info("blr   at 0x%08x: hooking %-10s\t%s\t%s -> %-10s\t%s\t%s" %
                     (i.address,
                      hexbytes(i.bytes), i.mnemonic, i.op_str,
                      hexbytes(instr.bytes), instr.mnemonic, instr.op_str))
    else:
        logging.warning("Disassembly failed at 0x%08x: Instruction could not be decoded." % i.address)
        return

    cfs_table.append(new_cfs(CFS.blr, i.bytes, i.address, None))  # No static target for `blr`, it's dynamic.

    if dry_run:
        return

    write_back(mm, i.address - load_address, word)


def rewrite_pop_fp_pc(mm, cfs_table, load_address, i, target, md, dry_run=False):
    word = new_branch_with_link_instruction(i, target)

    j = disasm_single(word, i.address, md)

    if j:
        instr = j[0]  

        logging.info("pop   at 0x%08x: hooking %-10s\t%s\t%s -> %-10s\t%s\t%s" %
                (i.address,
                    hexbytes(i.bytes), i.mnemonic, i.op_str,
                    hexbytes(instr.bytes), instr.mnemonic, instr.op_str))
    else:
        logging.warning("Disassembly failed at 0x%08x: Instruction could not be decoded." % i.address)
        return  

    cfs_table.append(new_cfs(CFS.pop_fp_pc, i.bytes, 0, 0))

    if dry_run:
        return

    write_back(mm, i.address - load_address, word)


def rewrite_pop_fp_lr(mm, cfs_table, load_address, i, target, md, dry_run=False):
    word = new_branch_with_link_instruction(i, target)

    j = disasm_single(word, i.address, md)

    if j:
        instr = j[0]  

        logging.info("pop   at 0x%08x: hooking %-10s\t%s\t%s -> %-10s\t%s\t%s" %
                (i.address,
                    hexbytes(i.bytes), i.mnemonic, i.op_str,
                    hexbytes(instr.bytes), instr.mnemonic, instr.op_str))
    else:
        logging.warning("Disassembly failed at 0x%08x: Instruction could not be decoded." % i.address)
        return  

    cfs_table.append(new_cfs(CFS.pop_fp_lr, i.bytes, 0, 0))

    if dry_run:
        return

    write_back(mm, i.address - load_address, word)


def rewrite_blx_rx(mm, cfs_table, load_address, i, target, md, dry_run=False):
    word = new_branch_with_link_instruction(i, target)

    j = disasm_single(word, i.address, md)

    if j:
        instr = j[0]  

        logging.info("blx rx at 0x%08x: hooking %-10s\t%s\t%s -> %-10s\t%s\t%s" %
                (i.address,
                    hexbytes(i.bytes), i.mnemonic, i.op_str,
                    hexbytes(instr.bytes), instr.mnemonic, instr.op_str))
    else:
        logging.warning("Disassembly failed at 0x%08x: Instruction could not be decoded." % i.address)
        return  

    cfs_table.append(new_cfs(CFS.blx_r3, i.bytes, 0, 0))

    if dry_run:
        return

    write_back(mm, i.address - load_address, word)


def hexbytes(insn):
    width = int(pow(2, math.ceil(math.log(len(insn))/math.log(2))))
    return "0x" + binascii.hexlify(bytearray(insn)).decode().zfill(width)

def get_current_pc(i):
    return i.address + 4

def get_target_offset(current_pc, target):
    return (target - current_pc) / 4 - 1  # pc relative offset of target

def get_target_address(current_pc, offset):
    return (offset * 4) + current_pc + 4  # absolute address of pc relative offset

def long_to_bytes(value, width=8, endian='big'):
    value = int(value)
    s = binascii.unhexlify(('%%0%dx' % (width)) % ((value + (1 << width*4)) % (1 << width*4)))
    return s[::-1] if endian == 'little' else s

def bytes_to_long(data, endian='big'):
    return int.from_bytes(data, byteorder=endian, signed=True)

def disasm_single(word, address, md):
    if isinstance(word, str):
        raise TypeError(f"Expected bytes, got str: {word}")
    
    if isinstance(word, int):  # If word is an integer, convert it to bytes
        word = word.to_bytes(4, byteorder="little")  
    
    return [i for i in md.disasm(word, address)]  


def write_back(mm, addr, word):
    mm.seek(addr)
    mm.write(word)

def get_branch_target(i):
    b = bitarray(endian="big")
    b.frombytes(i.bytes)

    return get_target_address(get_current_pc(i), bytes_to_long(bytearray(b[0:24].tobytes()), endian='little'))

def new_branch_with_link_instruction(i, target):
    bits = bitarray('0'*32, endian='big')

    bits[28:32] = bitarray('1011')  # opcode for BL
    bits[24:28] = cond_bits(i)      # condition bits from original instruction
    bits[00:24] = bytes_to_bits(long_to_bytes(
        get_target_offset(get_current_pc(i), target),
        width=6, endian='little'))

    return bytearray(bits.tobytes())

def cond_bits(i):
    bits = bitarray(endian='big')
    bits.frombytes(i.bytes)
    return bits[24:28]

def bytes_to_bits(data_bytes):
    if not isinstance(data_bytes, bytes):  # Ensure it is bytes
        raise TypeError(f"Expected bytes, got {type(data_bytes)}")
    bits = bitarray() 
    bits.frombytes(data_bytes)
    return bits


def write_branch_table(pathname, branches):
    with open(pathname, "w") as f:
        f.write("/* Automatically generated by %s on %s, do not edit! */\n\n" % (sys.argv[0], datetime.today()))
        f.write("#include \"lib/btbl.h\"\n\n")
        f.write("static __attribute__((section(\".btbl\"),unused)) struct btbl_entry btbl[] = {\n")

        for b in branches:
            f.write("\t{0x%08x,0x%08x},\n" % (b.src, b.dst))

        f.write("};\n")

def write_loop_table(pathname, loops):
    with open(pathname, "w") as f:
        f.write("/* Automatically generated by %s on %s, do not edit! */\n\n" % (sys.argv[0], datetime.today()))
        f.write("#include \"lib/ltbl.h\"\n\n")
        f.write("static __attribute__((section(\".ltbl\"),unused)) struct ltbl_entry ltbl[] = {\n")

        for (entry, exit) in loops:
            f.write("\t{0x%08x,0x%08x},\n" % (entry, exit))

        f.write("};\n")

if __name__ == "__main__":
    main()

