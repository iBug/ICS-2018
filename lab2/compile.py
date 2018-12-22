#!/usr/bin/python3

import sys
import os

import regex

INFILE = "ibug.lc3"
OUTFILE = "lab2.asm"
INS_FORMAT = "    {:36}; {}"
INS_FORMAT_RAW = "    {}"
INS_FORMAT_S = "{:40}; {}"
INS_FORMAT_S_RAW = "{}"


class RE:
    def_func = regex.compile(r"^def\s+(?P<name>\w+)\s*(?:\s|\((?=.*\)\s*$))\s*(?:(?P<args>\w+)(?:\s*,\s*(?P<args>\w+))*)?\)?\s*$")
    decl_vars = regex.compile(r"^\s*int\s+(?P<vars>\w+)(?:\s*,\s*(?P<vars>\w+))*")
    func_call = regex.compile(r"^\s*(?P<target>\w+)\s*=\s*(?P<name>\w+)\s*\((?:\s*(?P<args>\w+)(?:\s*,\s*(?P<args>\w+))*)?\)\s*$")

    TRAPS = {"GETC": 32, "OUT": 33, "PUTS": 34, "IN": 35, "PUTSP": 36, "HALT": 37}
    trap_call = regex.compile(r"^\s*(?P<target>\w+)\s*=\s*(?P<name>\L<trap>)\s*\(\s*(?P<args>\w+)?\)\s*$", trap=list(TRAPS))

    CONDITIONS = ["positive", "zero", "negative", "p", "n", "z"]
    branch = regex.compile(r"^\s*if\s+(?P<cond>\L<cond>)(?:\s+or\s+(?P<cond>\L<cond>))*\s*$", cond=CONDITIONS)

    SELF_OPERATORS = ["=", "+=", "&=", "~="]
    self_op = regex.compile(r"^\s*(?P<target>\w+)\s*(?P<op>\L<op>)\s*(?P<source>(?P<imm>-?\d+)|\w+)\s*$", op=SELF_OPERATORS)
    INTRA_OPERATORS = ["+", "&"]
    intra_op = regex.compile(r"^\s*(?P<target>\w+)\s*=\s*(?P<s1>\w+)\s*(?P<op>\L<op>)\s*(?P<s2>(?P<imm>-?\d+)|\w+)\s*$", op=INTRA_OPERATORS)

    KEYWORDS = ["return", "else", "end"]
    keyword_only = regex.compile(r"^\s*(?P<keyword>\L<w>)\s*$", w=KEYWORDS)
    SPECIAL_KEYWORDS = ["start", "done"]
    start_statement = regex.compile(r"^(?P<keyword>start)\s+(?P<name>\w+)\s*$")
    done_block = regex.compile(r"^(?P<keyword>done)")

    imm = regex.compile(r"(?<![-\d])-?\d+\b")


LABEL_PREFIX = "I_"


def func_label(name):
    return LABEL_PREFIX + "FUNCTION_{}".format(name.upper())


def end_func_label(name):
    return LABEL_PREFIX + "RETURN_FROM_{}".format(name.upper())


def branch_else_label(name, number):
    return LABEL_PREFIX + "COND_ELSE_{}_L{}".format(name.upper(), number)


def branch_end_label(name, number):
    return LABEL_PREFIX + "COND_END_{}_L{}".format(name.upper(), number)


def imm_label(name, value):
    if value < 0:
        number = "NEG_{}".format(-value)
    else:
        number = str(value)
    return LABEL_PREFIX + "IMM_{}_{}".format(name.upper(), number)


def lc3_int(value, pad=True):
    return "x" + ("{:04X}" if pad else "{:X}").format(value & 0xFFFF)


def add_instruction(container, s, comment=""):
    if s.lstrip()[0] == ".":
        if comment:
            container.append(INS_FORMAT_S.format(s, comment))
        else:
            container.append(INS_FORMAT_S_RAW.format(s))
    else:
        if comment:
            container.append(INS_FORMAT.format(s, comment))
        else:
            container.append(INS_FORMAT_RAW.format(s))


def compile_func(name, args, body):
    print("compile {}({})".format(name, ", ".join(args)))

    # Start with a label
    output = [func_label(name)]
    arg_count = len(args)
    vardict = {arg: arg_count - ind for ind, arg in enumerate(args)}

    # First count the local variables
    localvars = {}
    for i, line in enumerate(body, 1):
        match = RE.decl_vars.match(line)
        if match:
            print("Declared variables: [{}] {}".format(i, ", ".join(match.captures("vars"))))
            for var in match.captures("vars"):
                if var not in localvars:
                    localvars[var] = None
                else:
                    raise ValueError("Redefinition of local variable {}".format(var))
    localvar_count = len(localvars)

    # Shift up argument position (relative)
    for key in vardict:
        vardict[key] += localvar_count

    s = "ADD R6, R6, #{}".format(-localvar_count)
    comment = "Make {} space for local variables".format(localvar_count)
    add_instruction(output, s, comment)

    # Assign memory for local variables
    i = 0
    for key, value in localvars.items():
        i += 1
        vardict[key] = i

    #########################################
    ## Here comes the most exhaustive part ##
    #########################################
    need_imm = set()  # What big immediate numbers are needed?
    from_else = {}
    from_end = {}

    for i, line in enumerate(body, 1):
        # Compile every single line
        add_instruction(output, "; " + line.strip())

        match = RE.self_op.match(line)
        if match:
            reverse = False
            target = match.group("target")
            op = match.group("op")
            source = match.group("source")
            imm = match.group("imm")
            if imm is not None:
                imm = int(imm)

            if target != "_":  # One single underscore stands for R0
                if source == "_":  # R0 is occupied, use R1
                    reverse = True

                # Lookup variables
                var_pos = vardict[target]  # Stack offset of target variable
                if op not in {"=", "~="}:  # Not plain assignment or inverse
                    # Load variable first
                    comment = "Load var \"{}\"".format(target)
                    if reverse:
                        s = "LDR R1, R6, #{}".format(var_pos)
                    else:
                        s = "LDR R0, R6, #{}".format(var_pos)
                    add_instruction(output, s, comment)
            else:  # target is R0:
                pass

            if source != "_":  # Load source to R1
                if imm is not None:  # Handle immediate numbers
                    if -16 <= imm < 16:
                        comment = "Reset R1 to 0"
                        s = "AND R1, R1, #0"
                        add_instruction(output, s, comment)
                        if imm != 0:
                            comment = "Assign R1 = imm({})".format(imm)
                            s = "ADD R1, R1, #{}".format(imm)
                            add_instruction(output, s, comment)
                    else:  # Immediate number too big
                        comment = "Load R1 = imm({})".format(imm)
                        need_imm.add(imm)
                        s = "LD R1, {}".format(imm_label(name, imm))
                        add_instruction(output, s, comment)
                else:
                    comment = "Load var \"{}\"".format(source)
                    var_pos = vardict[source]
                    s = "LDR R1, R6, #{}".format(var_pos)
                    add_instruction(output, s, comment)

            # Perform the operation
            if op == "=":
                if reverse:  # Special handling of "x = _"
                    comment = "Store R0 to {}".format(target)
                    var_pos = vardict[target]
                    s = "STR R0, R6, #{}".format(var_pos)
                else:
                    comment = "Assign {1} to {0}".format(target, source)
                    if reverse:
                        s = "ADD R1, R0, #0"
                    else:
                        s = "ADD R0, R1, #0"
            elif op == "~=":
                comment = "Inverse {1} to {0}".format(target, source)
                if reverse:
                    s = "NOT R1, R0"
                else:
                    s = "NOT R0, R1"
            elif op == "+=":
                comment = "Add {1} to {0}".format(target, source)
                if reverse:
                    s = "ADD R1, R1, R0"
                else:
                    s = "ADD R0, R0, R1"
            elif op == "+=":
                comment = "Bitwise AND {1} to {0}".format(target, source)
                if reverse:
                    s = "AND R1, R1, R0"
                else:
                    s = "AND R0, R0, R1"
            else:
                raise ValueError("Unknown operator: {!r}".format(op))
            add_instruction(output, s, comment)

            # Store result if it's not like "x = _"
            if target != "_" and not (op == "=" and reverse):
                comment = "Store result to \"{}\"".format(target)
                var_pos = vardict[target]
                if reverse:
                    s = "STR R1, R6, #{}".format(var_pos)
                else:
                    s = "STR R1, R6, #{}".format(var_pos)
                add_instruction(output, s, comment)
            continue

        match = RE.intra_op.match(line)
        if match:
            reverse = False
            target = match.group("target")
            op = match.group("op")
            s1 = match.group("s1")
            s2 = match.group("s2")
            imm = match.group("imm")
            if imm is not None:
                imm = int(imm)

            # Load target to R0
            if target != "_":
                if s1 == "_":
                    reverse = True

                # Lookup variables
                var_pos = vardict[target]
                if op not in {"=", "~="}:  # Not plain assignment or inverse
                    # Load variable first
                    comment = "Load var \"{}\"".format(target)
                    if reverse:
                        s = "LDR R1, R6, #{}".format(var_pos)
                    else:
                        s = "LDR R0, R6, #{}".format(var_pos)
                    add_instruction(output, s, comment)
            else:  # target is R0:
                pass

            # Load s1 to R1
            if s1 != "_":
                var_pos = vardict[s1]
                comment = "Load var \"{}\"".format(s1)
                s = "LDR R1, R6, #{}".format(var_pos)
                add_instruction(output, s, comment)

            # Load s2 to R2
            if imm is not None:  # Handle immediate numbers
                if -16 <= imm < 16:
                    comment = "Reset R2 to 0"
                    s = "AND R2, R2, #0"
                    add_instruction(output, s, comment)
                    if imm != 0:
                        comment = "Assign R2 = imm({})".format(imm)
                        s = "ADD R2, R2, #{}".format(imm)
                        add_instruction(output, s, comment)
                else:  # Immediate number too big
                    comment = "Load R2 = imm({})".format(imm)
                    need_imm.add(imm)
                    s = "LD R2, {}".format(imm_label(name, imm))
                    add_instruction(output, s, comment)
            else:
                comment = "Load var \"{}\"".format(s2)
                var_pos = vardict[s2]
                s = "LDR R2, R6, #{}".format(var_pos)
                add_instruction(output, s, comment)

            # Perform the operation
            if op == "+":
                comment = "Add {1} and {2} to {0}".format(target, s1, s2)
                if reverse:
                    s = "ADD R1, R0, R2"
                else:
                    s = "ADD R0, R1, R2"
            elif op == "&":
                comment = "Bitwise AND {1} and {2} to {0}".format(target, s1, s2)
                if reverse:
                    s = "AND R1, R0, R2"
                else:
                    s = "AND R0, R1, R2"
            else:
                raise ValueError("Unknown operator: {!r}".format(op))
            add_instruction(output, s, comment)

            continue

        # Conditional
        match = RE.branch.match(line)
        if match:
            # conditions will only contain "n", "z" or "p"
            conditions = list(set([s[0] for s in match.captures("cond")]))
            conditions_inv = list(set("nzp") - set(conditions))
            conditions.sort(key=lambda s: {"n": 0, "z": 1, "p": 2}[s])
            conditions_inv.sort(key=lambda s: {"n": 0, "z": 1, "p": 2}[s])
            cond_key = "".join(conditions)
            cond_key_inv = "".join(conditions_inv)

            # Find the corresponding "else" and "end"
            depth = 0
            i_else = None
            i_end = None
            for line_no in range(i + 1, len(body) + 1):
                t = RE.branch.match(body[line_no - 1])
                if t:
                    depth += 1
                    continue
                t = RE.keyword_only.match(body[line_no - 1])
                if t:
                    if depth > 0:  # Not matching
                        if t.group("keyword") == "end":
                            depth -= 1
                        continue
                    # Haha, matching found
                    if t.group("keyword") == "else":
                        i_else = line_no
                    elif t.group("keyword") == "end":
                        i_end = line_no
                        break

            # Register the correspondence of "else" and "end"
            from_else[i_else] = i
            from_end[i_end] = i

            # Generate the BR instruction
            comment = "Branch when {}".format(cond_key)
            if i_else is None:  # No matching "else"
                s = "BR{} {}".format(cond_key_inv, branch_end_label(name, i))
            else:
                s = "BR{} {}".format(cond_key_inv, branch_else_label(name, i))
            add_instruction(output, s, comment)

            continue

        # TRAP must be placed before function call because they are otherwise identical
        match = RE.trap_call.match(line)
        if match:
            # Throw own R7 onto stack
            comment = "Save current R7 to stack"
            s = "STR R7, R6, #0"
            add_instruction(output, s, comment)

            target = match.group("target")
            trap_name = match.group("name")
            trap_id = RE.TRAPS[trap_name]

            # Generate TRAP
            comment = "TRAP to {} ({})".format(lc3_int(trap_id, False), trap_name)
            s = "TRAP {}".format(lc3_int(trap_id, False))
            add_instruction(output, s, comment)

            # Restore own R7 after TRAP
            comment = "Restore current R7 from stack"
            s = "LDR R7, R6, #0"
            add_instruction(output, s, comment)

            # Store the return value if it's not R0
            if target != "_":
                comment = "Store trap result to {}".format(target)
                var_pos = vardict[target]
                s = "STR R0, R6, #{}".format(var_pos)
                add_instruction(output, s, comment)
            continue

        match = RE.func_call.match(line)
        if match:
            # Throw own R7 onto stack
            comment = "Save current R7 to stack"
            s = "STR R7, R6, #0"
            add_instruction(output, s, comment)

            target = match.group("target")
            call_name = match.group("name")
            call_args = match.captures("args")
            call_arg_count = len(call_args)

            # Load variables and push them to stack
            for arg_index, call_arg in enumerate(call_args, 1):
                if call_arg == "_":
                    # Just throw R0 up!
                    comment = "Push R0 to stack as argument {}".format(arg_index)
                    s = "STR R0, R6, #{}".format(arg_index - call_arg_count - 1)
                    add_instruction(output, s, comment)
                elif RE.imm.match(call_arg):
                    # Call argument is an immediate number
                    imm = int(call_arg)
                    if -16 <= imm < 16:
                        comment = "Reset R1 to 0"
                        s = "AND R1, R1, #0"
                        add_instruction(output, s, comment)
                        if imm != 0:
                            comment = "Assign R1 = imm({})".format(imm)
                            s = "ADD R1, R1, #{}".format(imm)
                            add_instruction(output, s, comment)
                    else:  # Immediate number too big
                        comment = "Load R1 = imm({})".format(imm)
                        need_imm.add(imm)
                        s = "LD R1, {}".format(imm_label(name, imm))
                        add_instruction(output, s, comment)
                    comment = "Push imm({}) to stack as argument {}".format(imm, arg_index)
                    s = "STR R1, R6, #{}".format(arg_index - call_arg_count - 1)
                    add_instruction(output, s, comment)
                else:
                    comment = "Load var \"{}\"".format(call_arg)
                    var_pos = vardict[call_arg]
                    s = "LDR R1, R6, #{}".format(var_pos)
                    add_instruction(output, s, comment)

                    comment = "Push {} to stack as argument {}".format(call_arg, arg_index)
                    s = "STR R1, R6, #{}".format(arg_index - call_arg_count - 1)
                    add_instruction(output, s, comment)

            # Extend the stack
            comment = "Extend stack by {}".format(call_arg_count + 1)
            s = "ADD R6, R6, #{}".format(-call_arg_count - 1)
            add_instruction(output, s, comment)

            # Go Go Go!!!
            comment = "Call function \"{}\"".format(call_name)
            s = "JSR {}".format(func_label(call_name))
            add_instruction(output, s, comment)

            # Restore own R7 after function call
            comment = "Restore current R7 from stack"
            s = "LDR R7, R6, #0"
            add_instruction(output, s, comment)

            # Store the return value if it's not R0
            if target != "_":
                comment = "Store return value of {} to {}".format(call_name, target)
                var_pos = vardict[target]
                s = "STR R0, R6, #{}".format(var_pos)
                add_instruction(output, s, comment)
            continue

        match = RE.keyword_only.match(line)
        if match:
            keyword = match.group("keyword")
            if keyword == "return":
                comment = "Go to end of function \"{}\"".format(name)
                s = "BRnzp {}".format(end_func_label(name))
                add_instruction(output, s, comment)

            elif keyword == "else":
                # Lookup the corresponding "if"
                i_if = from_else[i]

                # End the previous block
                comment = "End of branch on line {}".format(i_if)
                s = "BR {}".format(branch_end_label(name, i_if))
                add_instruction(output, s, comment)

                # Generate a label for the "else" block
                output.append(branch_else_label(name, i_if))

            elif keyword == "end":
                # Generate a label for the "end" of the condition
                i_if = from_end[i]
                output.append(branch_end_label(name, i_if))
            continue

    # Before returning, there are things to do
    output.append(end_func_label(name))
    comment = "Restore stack"
    s = "ADD R6, R6, #{}".format(1 + len(vardict))
    add_instruction(output, s, comment)

    # Return
    add_instruction(output, "RET", "Return from {}".format(name))

    # Supply required immediate values
    for imm in sorted(need_imm):
        comment = "Immediate value {}".format(imm)
        s = ".FILL {}".format(lc3_int(imm))
        output.append(imm_label(name, imm))
        add_instruction(output, s, comment)
    print("\n".join(output))
    return output


def compile_start(match):
    print("compile start statement")
    name = "__START__"
    stack_bottom = -513
    output = []
    need_imm = {stack_bottom}

    s = "LD R6, {}".format(imm_label(name, stack_bottom))
    add_instruction(output, s, "Initialize stack")

    # Call the entry function
    entry = match.group("name")
    comment = "Go to entry function \"{}\"".format(entry)
    s = "JSR {}".format(func_label(entry))
    add_instruction(output, s, comment)

    add_instruction(output, "HALT")

    # Supply required immediate values
    for imm in sorted(need_imm):
        comment = "Immediate value {}".format(imm)
        s = ".FILL {}".format(lc3_int(imm))
        output.append(imm_label(name, imm))
        add_instruction(output, s, comment)

    print("\n".join(output))
    return output


def compile_lc3(lines):
    start = None
    blocks = []
    lines_iter = iter(lines)
    try:
        while True:
            # Scan for a function header, or "start"
            match = None
            while match is None:
                line = next(lines_iter)
                match = RE.def_func.match(line) or RE.start_statement.match(line)
            header = match

            if "keyword" in header.capturesdict():  # this is a "start" statement
                start = compile_start(header)
                continue

            # Now grab the body
            match = None
            body = []
            while True:
                line = next(lines_iter)
                match = RE.done_block.match(line)
                if match is not None:  # Stop on "done"
                    break
                body.append(line)
                continue

            name = header.group("name")
            args = header.captures("args")
            compiled = compile_func(name, args, body)
            blocks.append(compiled)
    except StopIteration:
        pass  # file done

    output = [".ORIG x3000"] + start + sum(blocks, []) + [".END"]
    return output


def main():
    with open(INFILE, "r") as f:
        lines = [line.rstrip() for line in f]

    compiled = compile_lc3(lines)

    with open(OUTFILE, "w") as f:
        print("\n".join(compiled), file=f)


if __name__ == "__main__":
    exit(main() or 0)
