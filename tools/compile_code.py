# encoding: utf8
import os
import sys
from elftools.elf.elffile import ELFFile
import argparse
import subprocess
import ubpf.disassembler
import struct

"""
ebpf code compiling tool, run in linux (or windows) python3.
clang (>= 3.7) is requried.
"""
CODE_TEMPLATE = """
const unsigned char ebpf_code[] = ""
BYTE_CODE
"";

"""

CODE_FILE = "ebpf_code.h"
CODEO = "code.o"
OUTPUT = None # "prog.bin"


def bytecode_to_str(byte_code):
	uc_str = "".join('\\x{:02x}'.format(c) for c in byte_code)
	print("code bytes: ", len(byte_code), len(uc_str));
	code_lines = []
	pos, li_sz = 0, 100
	while pos < len(uc_str):
		code_lines.append('"{}"'.format(uc_str[pos:pos+li_sz]))
		pos += li_sz
	fmt_str = "\n".join(code_lines)
	return fmt_str

def print_disasm(byte_code):
	print("disassemble: ")
	data = ubpf.disassembler.disassemble(byte_code)
	for pc, li in enumerate(data.split("\n")):
		if li:
			# print(pc + 1, li)
			print(li)
	print("")

def save_bpf_sec(sec, byte_code):
	out_path = CODE_FILE
	fmt_str = bytecode_to_str(byte_code)

	sec_name = sec.replace(".", "_").replace("/", "_")
	code = CODE_TEMPLATE.replace("ebpf_code", sec_name)
	code = code.replace("BYTE_CODE", fmt_str)
	print("save byte code to", out_path)
	with open(out_path, "a") as fp:
		fp.write(code)
	print_disasm(byte_code)

def bytes_to_str_escape(bys):
	return "".join('\\x{:02x}'.format(c) for c in bys)

def dump_elf_text(prog):
	# clear output
	with open(CODE_FILE, "w") as fp:
		fp.write("")

	# 从clang编译的二进制中导出prog
	with open(prog, "rb") as fp:
		elf = ELFFile(fp)
		for section in elf.iter_sections():
			sec_name = section.name.replace('"', "").replace("-", "_")
			if sec_name and sec_name.startswith("ewfd"):
				print(hex(section['sh_addr']), section.name)
				save_bpf_sec(sec_name, section.data())

		code = elf.get_section_by_name('.text')
		ops = code.data()
		if ops:
			save_bpf_sec("default", ops)

def compile_code(src):
	cmd = f"clang -O2 -emit-llvm -c {src} -o - | llc -march=bpf -filetype=obj -o code.o"
	# cmd = f"clang -O2 -target bpf -c {src} -o {CODEO} "
	exec_command(cmd, os.getcwd())
	if os.path.exists(CODEO):
		dump_elf_text(CODEO)

def assemble_to_bytecode(asm):
	# only support python2
	# import ubpf.assembler
	# code = ubpf.assembler.assemble(data)
	cmd = "python2 ubpf-assembler.py {} > code.o ".format(asm)
	exec_command(cmd)
	with open("code.o", "rb") as fp:
		code = fp.read()
	save_bpf_sec("default", ops)

def exec_command(cmd, cwd=os.getcwd()):
	print(f"Run cmd '{cmd}' in '{cwd}'")
	try:
		result = subprocess.run(cmd, cwd=cwd, shell=True) # capture_output=True
		if result.returncode != 0:
			msg = f"returncode: {result.returncode} cmd: '{result.args}' err:{result.stderr}"
			print("ERROR", msg)
			return False
	except Exception as ex:
		import traceback
		traceback.print_exc()
		return False
	return True

def setup_args():
	parser = argparse.ArgumentParser(prog="compile_ebpf", epilog="e.g. python3 compile_ebpf.py -s code.c")
	parser.add_argument("-s", "--src", metavar="src", help="choose ebpf src.")
	parser.add_argument("-a", "--asm", metavar="asm", help="compile asm.")
	parser.add_argument("-o", "--output", metavar="output", help="set output bin file.")
	parser.add_argument("-f", "--headerfile", metavar="header", help="set output header file.")
	args = parser.parse_args()
	if len(sys.argv) == 1:
	# if not any(vars(args).values()):
		parser.print_help()
		sys.exit(1)
	return args

def main():
	args = setup_args()
	if args.output:
		global OUTPUT
		OUTPUT = args.output
	if args.headerfile:
		global CODE_FILE
		CODE_FILE = args.headerfile
	if args.src:
		compile_code(args.src)
	elif args.asm:
		assemble_to_bytecode(args.asm)
	if os.path.exists(CODEO):
		os.remove(CODEO)

if __name__ == "__main__":
	main()