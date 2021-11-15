from llvmlite import ir
import binaryninja as bn

from .type_translator import to_llir_type
from .helpers import global_string_constant


class Traverser:
  def __init__(self, parser, func: bn.MediumLevelILFunction, ir_func: ir.Function):
    self.parser = parser
    self.function = func
    self.ir_function = ir_func
    self.basic_blocks = [bb for bb in func.ssa_form]
    self.ir_basic_blocks = []
    for bb in func.ssa_form:
      ir_block = self.ir_function.append_basic_block(f'{bb.index:x}')
      self.ir_basic_blocks.append((ir.IRBuilder(ir_block), ir_block))

    for block in self.basic_blocks:
      for instr in block:
        self.traverse(instr, self.ir_basic_blocks[block.index][1])

  def traverse(self, instr: bn.MediumLevelILInstruction, builder: ir.IRBuilder):
    ops = bn.mediumlevelil.MediumLevelILOperation
    if isinstance(instr, bn.mediumlevelil.MediumLevelILInstruction):
      print(f'  <MediumLevelILOperation, {str(instr.operation)}>')
      if instr.operation == ops.MLIL_SET_VAR_SSA:
        pass
      else:
        raise NotImplementedError(f'{str(instr.operation)} is not implemented')
    elif isinstance(instr, list):
      for entry in instr:
        self.traverse(entry, builder)
    else:
      print(f'<Not an operation, {type(instr)}, {str(instr)}>')
      raise ValueError


def translate_function_mlil(parser, func, ir_func):
  Traverser(parser, func.medium_level_il, ir_func)
