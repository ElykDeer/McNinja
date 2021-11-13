# 1. Sweep binary for global variables, create them
# 2. Sweep binary for (used?) external functions, declare those
# 3. Sweep binary for internal functions, translate them

from binaryninja.binaryview import BinaryView, SymbolType
from binaryninja.types import Symbol
from llvmlite import ir

from .type_translator import to_llir_type
from .hlil_translator import translate_fucntion

# TODO : Find a way to generate this, rather than hardcoding it
# SymbolType.DataSymbol
DATA_VAR_BLACKLIST = ["__elf_header",
                      "__elf_program_headers",
                      "__elf_interp",
                      "__abi_tag",
                      "__elf_symbol_table",
                      "_IO_stdin_used",
                      "__GNU_EH_FRAME_HDR",
                      "__FRAME_END__",
                      "__init_array_start",
                      "__init_array_end",
                      "__elf_dynamic_table",
                      "_GLOBAL_OFFSET_TABLE_",
                      "__data_start",
                      "__dso_handle",
                      "__TMC_END__"]

# TODO : Find a way to generate this, rather than hardcoding it
# SymbolType.FunctionSymbol
FUNCTION_BLACKLIST = ["_init",
                      "deregister_tm_clones",
                      "register_tm_clones",
                      "__libc_csu_init",
                      "__libc_csu_fini"]


class Parser():
  def __init__(self, bv: BinaryView):
    self.bv = bv

    self.module = ir.Module()

    self.global_vars = {}
    self.functions = {}

  # 1. Sweep binary for global variables, create them
  def phase_1(self):
    pass
    # # Step one is to parse out the system variables...ELFView headers and the like
    # for addr, data_var in self.bv.data_vars.items():
    #   if data_var.symbol is None:
    #     to_llir_type
    #   elif data_var.symbol.type == SymbolType.DataSymbol and data_var.symbol.name not in DATA_VAR_BLACKLIST:
    #     assert(False)  # TODO : All the symbols we've cared about so far haven't had symbols

  # 2. Sweep binary for (used?) external functions, declare those
  def phase_2(self):
    # We only care about ImportedFunctionSymbol's
    for func in self.bv.functions:
      if func.symbol.type == SymbolType.ImportedFunctionSymbol:
        self.functions[func.name] = ir.Function(self.module, to_llir_type(func.function_type), name=func.name)

  # 3. Sweep binary for internal functions, translate them
  def phase_3(self):
    for func in self.bv.functions:
      if func.symbol.type == SymbolType.FunctionSymbol and func.name not in FUNCTION_BLACKLIST:
        ir_func_type = to_llir_type(func.function_type)
        ir_func = ir.Function(self.module, ir_func_type, name=func.name)
        self.functions[func.name] = ir_func

        translate_fucntion(self.bv, self.module, func, ir_func)
