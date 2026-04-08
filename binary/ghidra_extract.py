# -*- coding: utf-8 -*-
# Ghidra script - extract functions, strings, call graph, and func-string refs
# Run this inside Ghidra: Script Manager -> Run
# Output: C:\Users\ADMIN\ghidra_output.json
#
# @author Kiro
# @category Analysis
# @menupath Tools.Extract Firmware Analysis Data

import json
import os

OUTPUT_PATH = r'C:\Users\ADMIN\ghidra_output.json'

# Helper functions

def addr_str(addr):
    return '0x{:08x}'.format(addr.getOffset())


def get_all_references_to(addr):
    ref_mgr = currentProgram.getReferenceManager()
    return list(ref_mgr.getReferencesTo(addr))


# 1. Extract functions

def extract_functions():
    functions = {}
    fm = currentProgram.getFunctionManager()

    for func in fm.getFunctions(True):
        entry = func.getEntryPoint()
        a = addr_str(entry)

        # Heuristic: treat functions with default FUN_ name as non-library
        name = func.getName()
        is_library = 0
        if func.isThunk() or func.isExternal():
            is_library = 1
        # If name looks like a real symbol (not FUN_xxxxxxxx), treat as library/known
        elif not name.startswith('FUN_') and not name.startswith('SUB_'):
            is_library = 1

        functions[a] = {
            'address': a,
            'name': name,
            'size': func.getBody().getNumAddresses(),
            'is_library': is_library,
            'entry_offset': entry.getOffset(),
        }

    print('[+] Functions: {}'.format(len(functions)))
    return functions


# 2. Extract strings

def extract_defined_strings():
    strings = {}
    listing = currentProgram.getListing()

    for data in listing.getDefinedData(True):
        dt_name = data.getDataType().getName().lower()
        if 'string' not in dt_name and 'char' not in dt_name:
            continue
        try:
            value = data.getValue()
            if value is None:
                continue
            s = str(value)
            if len(s) < 2:
                continue
            a = addr_str(data.getAddress())
            strings[a] = {
                'address': a,
                'content': s,
                'length': len(s),
                'addr_offset': data.getAddress().getOffset(),
            }
        except Exception:
            continue

    print('[+] Defined strings: {}'.format(len(strings)))
    return strings


def extract_raw_strings(min_len=5):
    """Scan memory for raw ASCII sequences not yet defined by Ghidra."""
    raw = {}
    memory = currentProgram.getMemory()

    for block in memory.getBlocks():
        if not block.isInitialized() or block.isExecute():
            continue  # Only scan data/rodata blocks

        addr = block.getStart()
        end  = block.getEnd()
        buf  = []
        buf_start = None

        while addr is not None and addr <= end:
            try:
                b = block.getByte(addr) & 0xFF
            except Exception:
                addr = addr.next()
                continue

            if (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D):
                if buf_start is None:
                    buf_start = addr
                buf.append(chr(b))
            else:
                if len(buf) >= min_len:
                    a = addr_str(buf_start)
                    if a not in raw:
                        raw[a] = {
                            'address': a,
                            'content': ''.join(buf).strip(),
                            'length': len(buf),
                            'addr_offset': buf_start.getOffset(),
                        }
                buf = []
                buf_start = None

            addr = addr.next()

        # Flush at block end
        if len(buf) >= min_len and buf_start is not None:
            a = addr_str(buf_start)
            if a not in raw:
                raw[a] = {
                    'address': a,
                    'content': ''.join(buf).strip(),
                    'length': len(buf),
                    'addr_offset': buf_start.getOffset(),
                }

    print('[+] Raw strings: {}'.format(len(raw)))
    return raw


# 3. Build function address map

def build_func_addr_map():
    """addr_offset (int) -> function address str"""
    fm = currentProgram.getFunctionManager()
    result = {}
    for func in fm.getFunctions(True):
        result[func.getEntryPoint().getOffset()] = addr_str(func.getEntryPoint())
    return result


# 4. Extract call graph

def extract_call_graph(func_addr_map):
    """
    Returns list of {caller, callee, call_addr}.
    Only includes edges where both caller and callee are known functions.
    """
    edges = []
    ref_mgr = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()

    for func in fm.getFunctions(True):
        caller_addr = addr_str(func.getEntryPoint())

        # Iterate all addresses in this function body
        body = func.getBody()
        addr_ranges = body.getAddressRanges()

        for rng in addr_ranges:
            a = rng.getMinAddress()
            while a is not None and a <= rng.getMaxAddress():
                for ref in ref_mgr.getReferencesFrom(a):
                    if ref.getReferenceType().isCall():
                        callee_offset = ref.getToAddress().getOffset()
                        callee_addr = func_addr_map.get(callee_offset)
                        if callee_addr and callee_addr != caller_addr:
                            edges.append({
                                'caller': caller_addr,
                                'callee': callee_addr,
                                'call_addr': addr_str(a),
                            })
                a = a.next()

    print('[+] Call graph edges: {}'.format(len(edges)))
    return edges


# 5. Extract func-string references

def extract_func_string_refs(all_strings, func_addr_map):
    """
    For each string, find all references to it and determine which function
    contains the referencing instruction.
    Returns list of {func_addr, string_addr, ref_addr}.
    """
    refs = []
    ref_mgr = currentProgram.getReferenceManager()
    fm = currentProgram.getFunctionManager()
    addr_factory = currentProgram.getAddressFactory()

    for s_addr_str, s_info in all_strings.items():
        try:
            target_addr = addr_factory.getDefaultAddressSpace().getAddress(s_info['addr_offset'])
        except Exception:
            continue

        for ref in ref_mgr.getReferencesTo(target_addr):
            from_addr = ref.getFromAddress()
            containing_func = fm.getFunctionContaining(from_addr)
            if containing_func is None:
                continue
            func_addr = addr_str(containing_func.getEntryPoint())
            refs.append({
                'func_addr': func_addr,
                'string_addr': s_addr_str,
                'ref_addr': addr_str(from_addr),
            })

    print('[+] Func-string refs: {}'.format(len(refs)))
    return refs


# Main

def main():
    print('[*] Starting firmware extraction...')
    print('[*] Program: {}'.format(currentProgram.getName()))

    functions    = extract_functions()
    def_strings  = extract_defined_strings()
    raw_strings  = extract_raw_strings(min_len=5)

    # Merge defined + raw strings (defined takes priority)
    all_strings = {}
    all_strings.update(raw_strings)
    all_strings.update(def_strings)
    print('[+] Total unique strings: {}'.format(len(all_strings)))

    func_addr_map     = build_func_addr_map()
    call_graph        = extract_call_graph(func_addr_map)
    func_string_refs  = extract_func_string_refs(all_strings, func_addr_map)

    output = {
        'program': currentProgram.getName(),
        'image_base': addr_str(currentProgram.getImageBase()),
        'functions': list(functions.values()),
        'strings': list(all_strings.values()),
        'call_graph': call_graph,
        'func_string_refs': func_string_refs,
    }

    with open(OUTPUT_PATH, 'w') as f:
        json.dump(output, f, indent=2)

    print('[+] Output written to: {}'.format(OUTPUT_PATH))
    print('[*] Done.')


main()
