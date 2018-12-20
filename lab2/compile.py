#!/usr/bin/python3

import sys
import os

import regex

INFILE = "ibug.lc3"
OUTFILE = "lab2.asm"


class RE:
    def_func = regex.compile(r"^def\s+(?P<name>\w+)\s*\((?:(?P<args>\w+)(?:\s*,\s*(?P<args>\w+))*)?\)")
    decl_vars = regex.compile(r"^\s*int\s+(?P<vars>\w+)(?:\s*,\s*(?P<vars>\w+))*")
    func_call = regex.compile(r"^\s*(?P<target>\w+)\s*=\s*(?P<name>\w+)\s*\((?:(?P<args>\w+)(?:\s*,\s*(?P<args>\w+))*)?\)")

    CONDITIONS = ["positive", "zero", "negative"]
    branch = regex.compile(r"^\s*(?P<cond>\L<cond>)(?:\s*,\s*(?P<cond>\L<cond>))*", cond=CONDITIONS)

    SELF_OPERATORS = ["=", "+=", "&=", "~="]
    self_op = regex.compile(r"^\s*(?P<target>\w+)\s*(?P<op>\L<op>)\s*(?P<source>-?\d+|\w+)", op=SELF_OPERATORS)
    INTRA_OPERATORS = ["+", "&", "~"]
    intra_op = regex.compile(r"^\s*(?P<target>\w+)\s*=\s*(?P<s1>-?\d+|\w+)\s*(?P<op>\L<op>)\s*(?P<s2>-?\d+|\w+)", op=INTRA_OPERATORS)

    KEYWORDS = ["return", "else", "end"]
    keyword_only = regex.compile(r"^\s*(?P<keyword>\L<w>)\s*$", w=KEYWORDS)
    SPECIAL_KEYWORDS = ["begin", "done"]
    begin_block = regex.compile(r"^(?P<keyword>begin)")
    done_block = regex.compile(r"^(?P<keyword>done)")


LABEL_PREFIX = "I_"


def func_label(name):
    return LABEL_PREFIX + "FUNC_{}".format(name.upper())


def branch_label(name, number):
    return LABEL_PREFIX + "COND_{}_L{}".format(name.upper(), number)


def compile_branch(name, body, vardict, line):
    pass


def compile_func(name, args, body):
    output = [func_label(name)]
    return output


def compile_begin(body):
    output = [".ORIG x3000"]
    return output


def compile_lc3(lines):
    begin = None
    blocks = []
    lines_iter = iter(lines)
    while True:
        # Scan for a function header, or "begin"
        match = None
        while match is None:
            line = next(lines_iter)
            match = RE.def_func.match(line) or RE.begin_block.match(line)
        header = match.capturesdict()

        # Now grab the body
        match = None
        body = []
        while True:
            line = next(lines_iter)
            match = RE.done_block.match(line)
            if match is None:
                body.append(line)
                continue
            else:
                break

        if "keyword" in header.capturesdict():  # this is a "begin" block
            begin = compile_begin(body)
        else:
            name = header.group("name")
            args = header.captures("args")
            compiled = compile_func(name, args, body)
            blocks.append(compiled)

    # TODO: Assemble the compiled stuff


def main():
    with open(INFILE, "r") as f:
        lines = [line.strip() for line in f]

    compiled = compile_lc3(lines)

    with open(OUTFILE, "w") as f:
        print("\n".join(compiled), file=f)


if __name__ == "__main__":
    exit(main() or 0)
