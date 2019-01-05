#!/usr/bin/python3

import sys
import os
from ast import literal_eval
import regex


re = regex.compile


class RE:
    class Basic:
        imm = r"(?:[Xx][0-9A-Fa-f]{1,4}|#?-?\d+)"
        label = r"(?:\b[^\W\d]\w*\b)"
        reg = r"(?:[Rr][0-7])"
        sep = r"(?:\s+|\s*,\s*)"
        string = r'"(?:[^"]|\\")*(?<!\\)"'

    # Strip comments
    comment = re(r'(?<!^(?:\\"|[^"])*(?<!\\)");.*$')
    empty = re(r"^\s*$")

    traps = r"(?:\b(?i:getc|out|puts|in|putsp|halt)\b)"
    insts = r"(?:\b(?i:add|and|ld[ir]?|st[ir]?|lea|br[nzp]*|jmp|jsrr?|not|ret|rti|trap|{})\b)".format(traps)
    dirs = r"(?:\.(?i:fill|blkw|stringz)\b)"

    orig = re(r"(?i)^\.orig\s+(?P<orig>{})$".format(Basic.imm))
    end = re(r"(?i)^\.end$".format(Basic.imm))
    label_only = re(r"^(?P<label>(?!{}|{}|{}){})$".format(traps, insts, Basic.imm, Basic.label))

    inst = re(r"^((?P<label>{0})\s+)?(?P<inst>{1})(?:\s+(?P<s>{2}|{3}|{4})(?:{5}(?P<s>{2}|{3}|{4}))*)?$".format(Basic.label, insts, Basic.imm, Basic.reg, Basic.label, Basic.sep), flags=2)
    directive = re(r"^(?P<label>{0})?\s*(?P<dir>{1})\s+(?P<s>{2}|{3})$".format(Basic.label, dirs, Basic.imm, Basic.string))


def lc3_int(s):
    if s[0] in "xX":
        return int(s[1:], 16)
    elif s[0] == "#":
        return int(s[1:])
    else:
        return int(s)
    raise ValueError("{!r} is not a LC-3 integer!".format(s))


def check_imm(val, width):
    if 0x8000 <= val < 0x10000:
        val -= 0x10000
    if val >= 2 ** (width - 1) or val < -(2 ** (width - 1)):
        raise ValueError("{} out of range for {}-bit immediate number".format(val, width))
    return val & (2 ** width - 1)


def parse_args(args):
    if not args:
        return []
    parsed = []
    for raw_arg in args:
        arg = raw_arg.upper()
        if arg[0] == "R" and arg[1].isdigit() and len(arg) == 2:
            if arg[1] not in "01234567":
                raise ValueError("Invalid register {}!".format(arg))
            parsed.append(("reg", int(arg[1])))
        elif RE.label_only.match(arg):
            parsed.append(("label", arg.upper()))
        elif re("^{}$".format(RE.Basic.string)).match(arg):
            parsed.append(("string", literal_eval(raw_arg)))  # Preserve case
        else:
            parsed.append(("int", lc3_int(arg)))
    return parsed


def parse_line(s):
    match = RE.label_only.match(s)
    if match:
        return (0, match.group("label"), None, None)

    match = RE.directive.match(s)
    if match:
        label, directive, args = match.group("label"), match.group("dir"), parse_args(match.captures("s"))
        if directive == ".FILL":
            return (1, label, directive, args)
        elif directive == ".BLKW":
            return (lc3_int(match.group("s")), label, directive, args)
        elif directive == ".STRINGZ":
            string = literal_eval(match.group("s"))
            return (1 + len(string), label, directive, args)

    match = RE.inst.match(s)
    if match:
        args = parse_args(match.captures("s"))
        return (1, match.group("label"), match.group("inst"), args)

    raise ValueError("What is this? {!r}".format(s))
    # Format: (length, label, instruction, (args...))
    return (0, None, None, None)


def build_symbol_table(lines, orig):
    symbols = dict()
    addr = orig
    for size, label, inst, args in lines:
        if label:
            if label.upper() in symbols:
                raise ValueError("Label {} already exists!".format(label))
            symbols[label.upper()] = addr
        addr += size
    return symbols


def translate_instructions(lines, orig, sym_table):
    out = bytearray(b"")

    def add_word(word):
        nonlocal out
        out.append((word >> 8) & 0xFF)
        out.append(word & 0xFF)

    def add_words(words):
        for word in words:
            add_word(word)

    add_word(orig)
    addr = orig
    for size, label, inst, args in lines:
        if not inst:
            continue
        inst = inst.upper()

        if inst == ".FILL":
            typ, val = args[0]
            if typ == "label":
                add_word(sym_table[val.upper()])
            elif typ == "int":
                add_word(val)
        elif inst == ".BLKW":
            typ, val = args[0]
            if typ != "int" or val <= 0:
                raise TypeError("Argument of .BLKW must be a positive integer!")
            add_words([0] * val)
        elif inst == ".STRINGZ":
            typ, val = args[0]
            if typ != "string":
                raise TypeError("Is it a string?")
            add_words(val.encode("utf-8") + b'\0')
        elif inst == "ADD" or inst == "AND":
            opcode = 0x1000 if inst == "ADD" else 0x5000
            dr, sr1 = args[0][1], args[1][1]
            typ, val = args[2]
            if typ == "reg":
                other = val
            else:
                other = check_imm(val, 5) | 0x20
            opcode |= (dr << 9) | (sr1 << 6) | (other)
            add_word(opcode)
        elif inst.startswith("BR"):
            conds = set(inst[2:])
            opcode = (("N" in conds) << 11) | (("Z" in conds) << 10) | (("P" in conds) << 9)
            typ, val = args[0]
            if typ == "label":
                val = sym_table[val.upper()] - addr - 1
            opcode |= check_imm(val, 9)
            add_word(opcode)
        elif inst == "JMP":
            target = args[0][1]
            opcode = 0xC000 | (target << 6)
            add_word(opcode)
        elif inst == "JSR":
            typ, val = args[0]
            if typ == "label":
                val = sym_table[val.upper()] - addr - 1
            opcode = 0x4800 | check_imm(val, 11)
            add_word(opcode)
        elif inst == "JSRR":
            target = args[0][1]
            opcode = 0x4000 | (target << 6)
            add_word(opcode)
        elif inst in {"LD", "LDI", "LEA", "ST", "STI"}:
            opcode = {
                "LD": 0x2000,
                "LDI": 0xA000,
                "LEA": 0xE000,
                "ST": 0x3000,
                "STI": 0xB000,
            }[inst]
            dr, (typ, val) = args[0][1], args[1]
            if typ == "label":
                val = sym_table[val.upper()] - addr - 1
            opcode |= (dr << 9) | check_imm(val, 9)
            add_word(opcode)
        elif inst in {"LDR", "STR"}:
            opcode = 0x6000 | ((inst == "STR") << 12)
            dr, br, off = args[0][1], args[1][1], args[2][1]
            opcode |= (dr << 9) | (br << 6) | check_imm(off, 6)
            add_word(opcode)
        elif inst == "NOT":
            dr, sr = args[0][1], args[1][1]
            opcode = 0x903F | (dr << 9) | (sr << 6)
            add_word(opcode)
        elif inst == "RET":
            add_word(0xC1C0)
        elif inst == "RTI":
            add_word(0x8000)
        elif inst == "TRAP":
            opcode = 0xF000 | args[0][1]
            add_word(opcode)
        elif inst in {"GETC", "OUT", "PUTS", "IN", "PUTSP", "HALT"}:
            vect = {
                "GETC": 0x20,
                "OUT": 0x21,
                "PUTS": 0x22,
                "IN": 0x23,
                "PUTSP": 0x24,
                "HALT": 0x25,
            }[inst]
            add_word(0xF000 | vect)
        else:
            raise ValueError("What is this? {!r}".format(inst))

        addr += size

    return out


def assemble_body(raw_lines, orig):
    lines = [parse_line(s) for s in raw_lines]

    print("STARTING PASS 1")
    sym_table = build_symbol_table(lines, orig)
    print("0 errors found in first pass.")

    print("STARTING PASS 2")
    out = translate_instructions(lines, orig, sym_table)
    print("0 errors found in second pass.")
    return sym_table, out


def format_symbol_table(symbols):
    header = "// Symbol table\n// Scope level 0:\n//  Symbol Name       Page Address\n//  ----------------  ------------\n"
    ls = list(symbols.items())
    ls.sort(key=lambda x: x[1])
    return header + "".join(["//  {}  {:04X}\n".format(name, addr) for name, addr in ls])


def main(args):
    # Process input file name
    if len(args) < 1:
        raise TypeError("Where's the file name?")
    filename = args[0]
    if filename.lower().endswith(".asm"):
        basename = filename[:-4]
    else:
        basename = filename
        filename += ".asm"
    if not os.path.exists(filename):
        raise FileNotFoundError("{} not found".format(filename))
    elif not os.path.isfile(filename):
        raise OSError("{} is not a regular file".format(filename))
    outname = basename + ".obj"
    symname = basename + ".sym"

    with open(filename, "r") as f:
        lines = [line.strip() for line in f]

    newlines = []
    for line in lines:
        line = RE.comment.sub("", line).strip()
        if line:
            newlines.append(line)
    lines = newlines

    out = bytearray()
    orig = body = None
    for line in lines:
        match = RE.orig.match(line)
        if match:
            orig = lc3_int(match.group("orig"))
            body = []
            continue

        match = RE.end.match(line)
        if match:
            symbols, assembled = assemble_body(body, orig)

            with open(outname, "wb") as f:
                f.write(assembled)
            with open(symname, "w") as f:
                print(format_symbol_table(symbols), file=f)
            orig = body = None
            continue

        if body is not None:
            body.append(line)


if __name__ == "__main__":
    try:
        r = main(sys.argv[1:])
        exit(r or 0)
    except Exception:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print("{}: {}".format(exc_type.__name__, exc_obj), file=sys.stderr)
        if "DEBUG" in os.environ:
            import traceback
            print("".join(traceback.format_tb(exc_tb)))
        else:
            exit(1)
