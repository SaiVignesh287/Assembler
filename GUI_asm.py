import tkinter as tk
from tkinter import scrolledtext, messagebox
import re

# Backend assembler functions

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
            binary_instruction = f"{opcode_bin}1{rd_bin}{rs1_bin}01{imm_bin}"
        else:
            rs2_bin = get_register_binary(rs2)
            binary_instruction = f"{opcode_bin}0{rd_bin}{rs1_bin}{rs2_bin}00000000000000"

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
            binary_instruction = f"{opcode_bin}0{rd_bin}{rs1_bin}{rs2_bin}00000000000000"
    
    # Additional instructions (e.g., mov, not) can be added here.
    
    return binary_instruction

opcodes = {
    "add": "00000", "sub": "00001", "mul": "00010", "div": "00011",
    "mod": "00100", "and": "00110", "or": "00111", "lsl": "01010",
    "lsr": "01011", "asr": "01100", "ld": "01110", "st": "01111",
    "not": "01000", "mov": "01001", "cmp": "00101", "nop": "01101",
    "ret": "10100", "beq": "10000", "bgt": "10001", "b": "10010",
    "call": "10011"
}

# GUI Code

root = tk.Tk()
root.title("SimpleRISC Assembler")

# Input text area
input_frame = tk.Frame(root)
input_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

input_label = tk.Label(input_frame, text="Input Assembly Code:")
input_label.pack(anchor="w")

input_text = scrolledtext.ScrolledText(input_frame, height=15, width=80)
input_text.pack(fill=tk.BOTH, expand=True)

# Output text area
output_frame = tk.Frame(root)
output_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

output_label = tk.Label(output_frame, text="Output Binary Code:")
output_label.pack(anchor="w")

output_text = scrolledtext.ScrolledText(output_frame, height=15, width=80)
output_text.pack(fill=tk.BOTH, expand=True)

# Assemble button action
def assemble_code():
    output_text.delete(1.0, tk.END)
    input_data = input_text.get(1.0, tk.END).strip()
    if not input_data:
        messagebox.showwarning("Input Error", "Please enter assembly code.")
        return
    results = []
    for line in input_data.splitlines():
        bin_instr = assemble_instruction(line, opcodes)
        if bin_instr:
            results.append(bin_instr)
        else:
            results.append("Error: Invalid instruction: " + line)
    output_text.insert(tk.END, "\n".join(results))

assemble_button = tk.Button(root, text="Assemble", command=assemble_code)
assemble_button.pack(pady=10)

root.mainloop()
