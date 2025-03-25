import re

def get_opcode_binary(mnemonic, opcodes):
    return opcodes.get(mnemonic)

def get_register_binary(reg):
    registers = {
        "R0": "0000", "R1": "0001", "R2": "0010", "R3": "0011",
        "R4": "0100", "R5": "0101", "R6": "0110", "R7": "0111",
        "R8": "1000", "R9": "1001", "R10": "1010", "R11": "1011",
        "R12": "1100", "R13": "1101", "R14": "1110", "R15": "1111",
    }
    return registers.get(reg.upper())

def int_to_binary(num, bits):
    return format((num + (1 << bits)) % (1 << bits), f'0{bits}b')

def is_number(s):
    return re.match(r'^-?\d+$', s) is not None

def assemble_instruction(instruction, opcodes):
    # Remove any comments or semicolon at the end.
    instruction = instruction.split(';')[0].strip()
    binary_instruction = ""
    parts = re.split(r'[, ]+', instruction)
    if len(parts) < 2:
        return None

    # Convert mnemonic to lowercase to ensure case-insensitive matching.
    mnemonic = parts[0].lower()
    opcode_bin = get_opcode_binary(mnemonic, opcodes)

    if not opcode_bin:
        return None

    if mnemonic in ["add", "sub", "mul", "div", "mod", "and", "or", "lsl", "lsr", "asr"]:
        if len(parts) < 4:
            return None
        rd, rs1, rs2 = parts[1], parts[2], parts[3]
        rd_bin = get_register_binary(rd)
        rs1_bin = get_register_binary(rs1)
        if is_number(rs2):
            imm_bin = int_to_binary(int(rs2), 16)
            # Format: opcode (5) + flag '1' (1) + rd (4) + rs1 (4) + "01" (2) + immediate (16)
            binary_instruction = f"{opcode_bin}1{rd_bin}{rs1_bin}01{imm_bin}"
        else:
            rs2_bin = get_register_binary(rs2)
            # Format: opcode (5) + flag '0' (1) + rd (4) + rs1 (4) + rs2 (4) + pad 16 zeros
            binary_instruction = f"{opcode_bin}0{rd_bin}{rs1_bin}{rs2_bin}" + "0" * 16

    elif mnemonic in ["ld", "st"]:
        if len(parts) < 3:
            return None
        rd, addr = parts[1], parts[2]
        match = re.match(r'(\w+)\[(\w+)\]', addr)
        if not match:
            return None
        rs2, rs1 = match.groups()
        rd_bin = get_register_binary(rd)
        rs1_bin = get_register_binary(rs1)
        if is_number(rs2):
            imm_bin = int_to_binary(int(rs2), 16)
            binary_instruction = f"{opcode_bin}1{rd_bin}{rs1_bin}01{imm_bin}"
        else:
            rs2_bin = get_register_binary(rs2)
            binary_instruction = f"{opcode_bin}0{rd_bin}{rs1_bin}{rs2_bin}" + "0" * 16

    elif mnemonic in ["mov", "not"]:
        # For mov (and not) we treat it as a type‑2 instruction.
        if len(parts) < 3:
            return None
        rd = parts[1]
        operand = parts[2]
        rd_bin = get_register_binary(rd)
        if is_number(operand):
            # Immediate operand: flag '1', fixed field "0000", mod "00", then 16-bit immediate.
            imm_bin = int_to_binary(int(operand), 16)
            # Format: opcode (5) + flag '1' (1) + rd (4) + fixed "0000" (4) + mod "00" (2) + immediate (16)
            binary_instruction = f"{opcode_bin}1{rd_bin}0000" + "00" + imm_bin
        else:
            # Register operand: flag '0', fixed field "0000", then source register.
            rs_bin = get_register_binary(operand)
            # Format: opcode (5) + flag '0' (1) + rd (4) + fixed "0000" (4) + source register (4) + pad with zeros to 32 bits.
            binary_instruction = f"{opcode_bin}0{rd_bin}0000{rs_bin}"
            binary_instruction = binary_instruction.ljust(32, '0')
    else:
        # Unsupported mnemonic.
        return None

    return binary_instruction

# Opcodes mapping.
opcodes = {
    "add": "00000", "sub": "00001", "mul": "00010", "div": "00011",
    "mod": "00100", "and": "00110", "or": "00111", "lsl": "01010",
    "lsr": "01011", "asr": "01100", "ld": "01110", "st": "01111",
    "not": "01000", "mov": "01001", "cmp": "00101", "nop": "01101",
    "ret": "10100", "beq": "10000", "bgt": "10001", "b": "10010",
    "call": "10011", "hlt": "11111"
}

input_file = "output.asm"
output_file = "output.bin"

print("Assembling...")

try:
    with open(input_file, "r") as infile, open(output_file, "w") as outfile:
        for line in infile:
            binary = assemble_instruction(line, opcodes)
            if binary:
                outfile.write(binary + "\n")
    print("Assembly complete. Output written to", output_file)
except FileNotFoundError:
    print("Error: Input file not found.")
