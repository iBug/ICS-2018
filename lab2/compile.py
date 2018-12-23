#!/usr/bin/python3

import sys
import os

try:
    import regex
except ImportError as e:
    print("{}: {}".format(type(e).__name__, str(e)), "Did you install regex from PyPI?\nTry running\n\n    pip3 install regex\n", file=sys.stderr, sep="\n")
    exit(1)

DEFAULT_INFILE = "ibug.lc3"
DEFAULT_OUTFILE = "lab2.asm"
INS_FORMAT = "    {:36}; {}"
INS_FORMAT_RAW = "    {}"
INS_FORMAT_S = "{:40}; {}"
INS_FORMAT_S_RAW = "{}"


class RE:
    def_func = regex.compile(r"^def\s+(?P<name>\w+)\s*(?:$|\s(?=[^)]*$)|\((?=.*\)\s*$))\s*(?:(?P<args>\w+)(?:\s*,\s*(?P<args>\w+))*)?\)?\s*$")
    decl_vars = regex.compile(r"^\s*var\s+(?P<vars>\w+)(?:\s*,\s*(?P<vars>\w+))*\s*$")
    func_call = regex.compile(r"^\s*(?P<target>\w+)\s*=\s*(?P<name>\w+)\s*\((?:\s*(?P<args>\w+|-?\d+)(?:\s*,\s*(?P<args>\w+|-?\d+))*)?\)\s*$")

    TRAPS = {"GETC": 32, "OUT": 33, "PUTS": 34, "IN": 35, "PUTSP": 36, "HALT": 37}
    trap_call = regex.compile(r"^\s*(?P<target>\w+)\s*=\s*(?P<name>\L<trap>)\s*\(\s*(?P<args>\w+)?\)\s*$", trap=list(TRAPS))

    COMPARATORS = {"<": "n", ">": "p", "<=": "nz", ">=": "zp", "==": "z", "!=": "np"}
    branch = regex.compile(r"^\s*if\s+(?P<s1>\w+)\s*(?P<op>\L<comp>)\s*(?P<s2>(?P<imm>-?\d+)|\w+)\s*$", comp=list(COMPARATORS))
    loop = regex.compile(r"^\s*while\s+(?P<s1>\w+)\s*(?P<op>\L<comp>)\s*(?P<s2>(?P<imm>-?\d+)|\w+)\s*$", comp=list(COMPARATORS))

    SELF_OPERATORS = ["=", "+=", "&=", "~="]
    self_op = regex.compile(r"^\s*(?P<target>\w+)\s*(?P<op>\L<op>)\s*(?P<source>(?P<imm>-?\d+)|\w+)\s*$", op=SELF_OPERATORS)
    INTRA_OPERATORS = ["+", "&"]
    intra_op = regex.compile(r"^\s*(?P<target>\w+)\s*=\s*(?P<s1>\w+)\s*(?P<op>\L<op>)\s*(?P<s2>(?P<imm>-?\d+)|\w+)\s*$", op=INTRA_OPERATORS)

    KEYWORDS = ["return", "else", "end"]
    keyword_only = regex.compile(r"^\s*(?P<keyword>\L<w>)\s*$", w=KEYWORDS)
    start_statement = regex.compile(r"^(?P<keyword>start)\s+(?P<name>\w+)\s*$")

    imm = regex.compile(r"(?<![-\d])-?\d+\b")

    increase_level = [branch, loop]  # These statements increast cognitive depth


LABEL_PREFIX = "I_"


def func_label(name):
    return LABEL_PREFIX + "FUNCTION_{}".format(name.upper())


def end_func_label(name):
    return LABEL_PREFIX + "RETURN_FROM_{}".format(name.upper())


def branch_else_label(name, number):
    return LABEL_PREFIX + "COND_ELSE_{}_L{}".format(name.upper(), number)


def branch_end_label(name, number):
    return LABEL_PREFIX + "COND_END_{}_L{}".format(name.upper(), number)


def loop_body_label(name, number):
    return LABEL_PREFIX + "LOOP_BODY_{}_L{}".format(name.upper(), number)


def loop_cond_label(name, number):
    return LABEL_PREFIX + "LOOP_CHECK_{}_L{}".format(name.upper(), number)


def imm_label(name, value):
    if value < 0:
        number = "NEG_{}".format(-value)
    else:
        number = str(value)
    return LABEL_PREFIX + "IMM_{}_{}".format(name.upper(), number)


def error_label(name):
    return LABEL_PREFIX + "ERR_" + name.upper().replace(" ", "_")


def lc3_int(value, pad=True):
    return "x" + ("{:04X}" if pad else "{:X}").format(value & 0xFFFF)


def add_instruction(container, s, comment=""):
    if s.lstrip()[0] == ".":  # Begins with a dot
        if comment:
            container.append(INS_FORMAT_S.format(s, comment))
        else:
            container.append(INS_FORMAT_S_RAW.format(s))
    else:
        if comment:
            container.append(INS_FORMAT.format(s, comment))
        else:
            container.append(INS_FORMAT_RAW.format(s))


def load_variable(output, target, vardict, varname):
    assert isinstance(output, list) and isinstance(vardict, dict)
    assert regex.match("(?i)^R[0-7]$", target)
    target = target.upper()
    comment = "Load var \"{}\"".format(varname)
    var_pos = vardict[varname]  # Lookup from vardict
    s = "LDR {}, R6, #{}".format(target, var_pos)
    add_instruction(output, s, comment)


def create_imm(name, output, need_imm, target, imm):
    assert isinstance(output, list) and isinstance(need_imm, set)
    assert regex.match("(?i)^R[0-7]$", target)
    target = target.upper()

    # Expand numbers between -64 and 60
    if -64 <= imm <= 60:
        comment = "Reset {} to 0".format(target)
        s = "AND {0}, {0}, #0".format(target)
        add_instruction(output, s, comment)

        # Expand numbers between -64 and +60
        comment = "Assign {} = imm({})".format(target, imm)
        if imm > 0:
            s = "ADD {0}, {0}, #15".format(target)
            while imm > 15:
                add_instruction(output, s)
                imm -= 15
            s = "ADD {0}, {0}, #{1}".format(target, imm)
            add_instruction(output, s, comment)
        elif imm < 0:
            s = "ADD {0}, {0}, #-16".format(target)
            while imm < -16:
                add_instruction(output, s)
                imm += 16
            s = "ADD {0}, {0}, #{1}".format(target, imm)
            add_instruction(output, s, comment)
    else:  # Immediate number too big
        comment = "Load {} = imm({})".format(target, imm)
        need_imm.add(imm)
        s = "LD {}, {}".format(target, imm_label(name, imm))
        add_instruction(output, s, comment)


def compile_func(name, args, body):
    print("compile {}({})".format(name, ", ".join(args)))

    # Start with a label
    output = [func_label(name)]
    arg_count = len(args)
    vardict = {arg: ind for ind, arg in enumerate(args, 1)}

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

    # Check stack overflow
    comment = "Add the inverse of predefined stack top"
    add_instruction(output, "ADD R1, R6, R5", comment)
    comment = "Check for stack overflow"
    s = "BRn {}".format(error_label("stack overflow"))
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
    loop_end = {}

    for i, line in enumerate(body, 1):
        # Ignore comments
        if line.lstrip()[0] == "#":
            continue
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

                # Load target variable
                if op not in {"=", "~="}:  # Not plain assignment or inverse
                    load_variable(output, "R1" if reverse else "R0", vardict, target)
            else:  # target is R0:
                pass

            if source != "_":  # Load source to R1
                if imm is not None:  # Handle immediate numbers
                    create_imm(name, output, need_imm, "R1", imm)
                else:
                    # Special handling for "_ = x"
                    if target == "_" and op == "=":
                        comment = "Load var \"{}\" to _".format(source)
                        var_pos = vardict[source]
                        s = "LDR R0, R6, #{}".format(var_pos)
                        add_instruction(output, s, comment)
                        continue
                    else:
                        load_variable(output, "R1", vardict, source)

            # Perform the operation
            if op == "=":
                if reverse:  # Special handling of "x = _"
                    comment = "Store R0 to {}".format(target)
                    var_pos = vardict[target]
                    s = "STR R0, R6, #{}".format(var_pos)
                elif target != "_":
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
                    s = "STR R0, R6, #{}".format(var_pos)
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
                    load_variable(output, "R1" if reverse else "R0", vardict, target)
            else:  # target is R0:
                pass

            # Load s1 to R1
            if s1 != "_":
                load_variable(output, "R1", vardict, s1)

            # Load s2 to R2
            if imm is not None:  # Handle immediate numbers
                create_imm(name, output, need_imm, "R2", imm)
            else:
                load_variable(output, "R2", vardict, s2)

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
            s1 = match.group("s1")
            operator = match.group("op")
            s2 = match.group("s2")
            imm = match.group("imm")
            if imm:
                imm = int(imm)

            # Condition key, like BRnzp
            #                       ^^^
            cond_key = RE.COMPARATORS[operator]
            cond_key_inv = list(set("nzp") - set(cond_key))
            cond_key_inv.sort(key=lambda s: {"n": 0, "z": 1, "p": 2}[s])
            cond_key_inv = "".join(cond_key_inv)

            # Find the corresponding "else" and "end"
            depth = 0
            i_else = None
            i_end = None
            for line_no in range(i + 1, len(body) + 1):
                # Another branch or loop should increase depth
                for deepen_re in RE.increase_level:
                    if deepen_re.match(body[line_no - 1]):
                        depth += 1
                        break
                else:
                    t = RE.keyword_only.match(body[line_no - 1])
                    if t:
                        if depth > 0:  # Not matching
                            if t.group("keyword") == "end":
                                depth -= 1
                            continue
                        # Haha, matching keyword found
                        if t.group("keyword") == "else":
                            i_else = line_no
                        elif t.group("keyword") == "end":
                            i_end = line_no
                            break
            # Register the correspondence of "else" and "end"
            from_else[i_else] = i
            from_end[i_end] = i

            # Prepare the left operand
            load_variable(output, "R1", vardict, s1)

            # Prepare the right operand
            if imm is not None:  # right operand is immediate value
                # Go directly for the inverse of the immediate value
                create_imm(name, output, need_imm, "R2", -imm)
            else:
                # Load value
                load_variable(output, "R2", vardict, s2)

                # Manually inverse R2
                comment = "Inverse {}".format(s2)
                add_instruction(output, "NOT R2, R2")
                add_instruction(output, "ADD R2, R2, #1", comment)

            # Perform the comparison
            comment = "Compare {} with {}".format(s1, s2)
            add_instruction(output, "ADD R1, R1, R2", comment)

            # Generate branch instruction
            comment = "Branch when {}".format(cond_key)
            if i_else is None:  # No matching "else"
                s = "BR{} {}".format(cond_key_inv, branch_end_label(name, i))
            else:
                s = "BR{} {}".format(cond_key_inv, branch_else_label(name, i))
            add_instruction(output, s, comment)
            continue

        # Loop
        match = RE.loop.match(line)
        if match:
            s1 = match.group("s1")
            operator = match.group("op")
            s2 = match.group("s2")
            imm = match.group("imm")
            if imm:
                imm = int(imm)

            # Condition key, like BRnzp
            #                       ^^^
            cond_key = RE.COMPARATORS[operator]
            cond_key_inv = list(set("nzp") - set(cond_key))
            cond_key_inv.sort(key=lambda s: {"n": 0, "z": 1, "p": 2}[s])
            cond_key_inv = "".join(cond_key_inv)

            # Find the corresponding "else" and "end"
            depth = 0
            i_else = None
            i_end = None
            for line_no in range(i + 1, len(body) + 1):
                # Another branch or loop should increase depth
                for deepen_re in RE.increase_level:
                    if deepen_re.match(body[line_no - 1]):
                        depth += 1
                        break
                else:
                    t = RE.keyword_only.match(body[line_no - 1])
                    if t and t.group("keyword") == "end":
                        if depth > 0:  # Not matching
                            depth -= 1
                            continue
                        else:  # Matching
                            i_end = line_no
                            break

            # We're going to optimize into tail jump
            # https://stackoverflow.com/q/47783926/5958455

            # Prepare all the instructions for "end"
            end_inst = []

            # Prepare the left operand
            load_variable(end_inst, "R1", vardict, s1)

            # Prepare the right operand
            if imm is not None:  # right operand is immediate value
                # Go directly for the inverse of the immediate value
                create_imm(name, end_inst, need_imm, "R2", -imm)
            else:
                load_variable(end_inst, "R2", vardict, s2)

                # Manually inverse R2
                comment = "Inverse {}".format(s2)
                add_instruction(end_inst, "NOT R2, R2")
                add_instruction(end_inst, "ADD R2, R2, #1", comment)

            # Perform the comparison
            comment = "Compare {} with {}".format(s1, s2)
            add_instruction(end_inst, "ADD R1, R1, R2", comment)

            # Jump back to loop start if true
            comment = "Jump back to loop start when {}".format(cond_key)
            s = "BR{} {}".format(cond_key, loop_body_label(name, i))
            add_instruction(end_inst, s, comment)

            # Register the correspondence of "end" and save these prepared instructions
            loop_end[i_end] = (i, end_inst)

            # Generate branch instruction here
            comment = "Go to loop condition check"
            s = "BRnzp {}".format(loop_cond_label(name, i))
            add_instruction(output, s, comment)

            output.append(loop_body_label(name, i))
            continue

        # TRAP must be placed before function call because they are otherwise identical
        # or TRAP may be picked up as a function call
        match = RE.trap_call.match(line)
        if match:
            # Throw own R7 onto stack
            comment = "Save current R7 to stack"
            s = "STR R7, R6, #0"
            add_instruction(output, s, comment)

            target = match.group("target")
            trap_name = match.group("name")
            trap_id = RE.TRAPS[trap_name]
            trap_args = match.captures("args")

            # Process arguments
            if len(trap_args) > 0 and trap_args[0] != "_":  # Probably don't need to process _ (aka R0)
                load_variable(output, "R0", vardict, trap_args[0])

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
                    create_imm(name, output, need_imm, "R1", imm)

                    comment = "Push imm({}) to stack as argument {}".format(imm, arg_index)
                    s = "STR R1, R6, #{}".format(arg_index - call_arg_count - 1)
                    add_instruction(output, s, comment)
                else:
                    load_variable(output, "R1", vardict, call_arg)

                    comment = "Push {} to stack as argument {}".format(call_arg, arg_index)
                    s = "STR R1, R6, #{}".format(arg_index - call_arg_count - 1)
                    add_instruction(output, s, comment)

            # Extend the stack
            comment = "Extend stack by {}".format(call_arg_count + 1)
            s = "ADD R6, R6, #{}".format(-call_arg_count - 1)
            add_instruction(output, s, comment)

            # Check stack overflow
            comment = "Add the inverse of predefined stack top"
            add_instruction(output, "ADD R1, R6, R5", comment)
            comment = "Check for stack overflow"
            s = "BRn {}".format(error_label("stack overflow"))
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
                if i in from_end:
                    # Generate a label for the "end" of the branch
                    i_if = from_end[i]
                    output.append(branch_end_label(name, i_if))
                elif i in loop_end:
                    i_while, end_inst = loop_end[i]
                    # Generate a label for the condition check
                    output.append(loop_cond_label(name, i_while))
                    # Take the pre-generated instructions and put them here
                    output.extend(end_inst)
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
    # print("\n".join(output))
    return output


def compile_stack_overflow():
    output = [error_label("stack_overflow")]

    # Print a predefined error message
    s = "LEA R0, {}".format(error_label("stack_overflow_text"))
    add_instruction(output, s, "Load error message")

    trap_name, trap_id = "PUTS", 34
    comment = "TRAP to {} ({})".format(lc3_int(trap_id, False), trap_name)
    s = "TRAP {}".format(lc3_int(trap_id, False))
    add_instruction(output, s, comment)

    add_instruction(output, "HALT")
    output.append(error_label("stack_overflow_text"))
    add_instruction(output, ".STRINGZ \"Stack overflow detected!\"", "Predefined error message")
    return output


def compile_start(match):
    print("compile start statement")
    name = "START"
    stack_bottom = -513
    stack_top = stack_bottom - 511
    output = []
    need_imm = {stack_bottom, -stack_top}  # Stack top is inversed for faster subtraction

    s = "LD R6, {}".format(imm_label(name, stack_bottom))
    add_instruction(output, s, "Initialize stack")
    s = "LD R5, {}".format(imm_label(name, -stack_top))
    add_instruction(output, s, "Initialize stack limit")

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

    # Append the stack overflow handler code
    output.extend(compile_stack_overflow())

    # print("\n".join(output))
    return output


def compile_lc3(lines):
    start = None
    blocks = []
    lines_iter = iter(enumerate(lines, 1))
    try:
        while True:
            # Scan for a function header, or "start"
            match = None
            while match is None:
                line_no, line = next(lines_iter)
                match = RE.def_func.match(line) or RE.start_statement.match(line)
            header = match

            if "keyword" in header.capturesdict():  # this is a "start" statement
                start = compile_start(header)
                continue

            # Now grab the body
            match = None
            body = []
            depth = 0
            while True:
                line_no, line = next(lines_iter)
                for deepen_re in RE.increase_level:
                    match = deepen_re.match(line)
                    if match is not None:  # ifs and whiles increase cognitive depth
                        depth += 1
                        break
                else:
                    match = RE.keyword_only.match(line)
                    if match and match.group("keyword") == "end":
                        if depth == 0:  # matching "end" found
                            break
                        else:
                            depth -= 1
                body.append(line)
                continue

            name = header.group("name")
            if name == "start":
                raise ValueError("Function name cannot be \"start\"")
            args = header.captures("args")
            compiled = compile_func(name, args, body)
            blocks.append(compiled)
    except StopIteration:
        pass  # file done

    output = [".ORIG x3000"] + start + sum(blocks, []) + [".END"]
    return output


def main(infile, outfile):
    print("Input file: {}".format(infile))
    print("Output file: {}".format(outfile))
    print()

    with open(infile, "r") as f:
        lines = [line.rstrip() for line in f]

    compiled = compile_lc3(lines)

    with open(outfile, "w") as f:
        print("\n".join(compiled), file=f)


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc == 1:
        infile = DEFAULT_INFILE
        outfile = DEFAULT_OUTFILE
    elif argc == 3:
        infile = sys.argv[1]
        outfile = sys.argv[2]
    else:
        raise ValueError("Wrong number of arguments")

    if not os.path.isfile(infile):
        raise OSError("Input file is invalid")
    elif os.path.exists(outfile) and not os.path.isfile(outfile):
        raise OSError("Output file is invalid")

    exit(main(infile, outfile) or 0)
