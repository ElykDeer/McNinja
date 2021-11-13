from llvmlite import ir
import binaryninja as bn
from .type_translator import to_llir_type


def traverse_il_block(il, module, builder):
  ops = bn.highlevelil.HighLevelILOperation
  if isinstance(il, bn.highlevelil.HighLevelILInstruction):
    print(f'<HighLevelILOperation, {str(il.operation)}>')

    if il.operation == ops.HLIL_CALL_SSA:
      traverse_il_block(il.dest, module, builder)
      for operand in il.params:
        traverse_il_block(operand, module, builder)

    if il.operation == ops.HLIL_CONST_PTR:
      print(f'<HLIL_CONST_PTR, {hex(il.constant)}>')

    if il.operation == ops.HLIL_CONST:
      print(f'<HLIL_CONST, {hex(il.constant)}>')

    if il.operation == ops.HLIL_RET:
      for operand in il.operands:
        traverse_il_block(operand, module, builder)

  elif isinstance(il, list):
    for entry in il:
      traverse_il_block(entry, module, builder)
  else:
    print(f'<Not an operation, {type(il)}, {str(il)}>')


def translate_function(bv, module, func, ir_func):
  for bb in func.high_level_il.ssa_form:
    ir_bb = ir_func.append_basic_block()
    builder = ir.IRBuilder(ir_bb)
    for instr in bb:
      traverse_il_block(instr, module, builder)
