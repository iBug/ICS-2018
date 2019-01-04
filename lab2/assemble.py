#!/usr/bin/python3

import sys
import os
import regex


re = regex.compile


class RE:
    class Basic:
        imm = r"(?:[Xx][0-9A-Fa-f]{1,4}|#?-?\d+)"
        label = r"(?:\b[^\W\d]\w*\b)"
        reg = r"(?:[Rr][0-7])"
        sep = r"(?:\s+|\s*,\s*)"

    # Strip comments
    comment = re(r'(?<!^(?:\\"|[^"])*(?<!\\)");.*$')
    empty = re(r"^\s*$")

    traps = r"(?:\b(?i:getc|out|puts|in|putsp|halt)\b)"
    insts = r"(?:\b(?i:add|and|ld[ir]?|st[ir]?|lea|br[nzp]*|jmp|jsrr?|not|ret|rti|trap|{})\b)".format(traps)
    dirs = r"(?:\.(?i:fill|blkw|stringz)\b)"

    orig = re(r"(?i)^\.orig\s+(?P<orig>{})$".format(Basic.imm))
    end = re(r"(?i)^\.end$".format(Basic.imm))
    label_only = re(r"^(?P<label>(?!{}|{}){})$".format(traps, insts, Basic.label))

    inst = re(r"^((?P<label>{0})\s+)?(?P<inst>{1})\s+(?:(?P<s>{2}|{3}|{4})(?:{5}(?P<s>{2}|{3}|{4}))*)?$".format(Basic.label, insts, Basic.imm, Basic.reg, Basic.label, Basic.sep))
    directive = re(r"^(?P<label>{0})?\s*(?P<dir>{1})\s+(?P<s>{2})$".format(Basic.label, dirs, Basic.imm))


def lc3_int(s):
    if s[0] in "xX":
        return int(s[1:], 16)
    elif s[0] == "#":
        return int(s[1:])
    else:
        return int(s)


def parse_line(s):
    return ()


def assemble_body(lines, orig):
    out = bytearray()
    addr = orig
    return out


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

    with open(filename, "r") as f:
        lines = [line.strip() for line in f]

    newlines = []
    for line in lines:
        line = RE.comment.sub("", line).strip()
        if line:
            newlines.append(line)
    lines = newlines

    out = bytearray()
    orig = body = None;
    for line in lines:
        match = RE.orig.match(line)
        if match:
            orig = lc3_int(match.group("orig"))
            body = []
            continue

        match = RE.end.match(line)
        if match:
            assembled = assemble_body(body, orig)
            out.extend(assembled)
            orig = body = None
            continue

        if body is not None:
            body.append(line)

    with open(outname, "wb") as f:
        f.write(out)

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
