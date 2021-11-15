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

    # TODO: Considering doing a sweep and creating/storing every MLIL_SET_VAR_SSA
    # TODO: inside of LLIR and caching it with its block so phi nodes can be handled easier
    for bb in func.ssa_form:
      ir_block = self.ir_function.append_basic_block(f'{bb.index:x}')
      self.ir_basic_blocks.append((ir.IRBuilder(ir_block), ir_block))

    for block in self.basic_blocks:
      print(f'{block.index}:{block}')
      for instr in block:
        self.traverse(instr, self.ir_basic_blocks[block.index][0])

  def traverse(self, instr: bn.MediumLevelILInstruction, builder: ir.IRBuilder, var=None):
    ops = bn.mediumlevelil.MediumLevelILOperation
    if isinstance(instr, bn.mediumlevelil.MediumLevelILInstruction):
      print(f'  <MediumLevelILOperation, {str(instr.operation)}>')
      if instr.operation == ops.MLIL_SET_VAR_SSA:
        dest: bn.SSAVariable = instr.dest
        llir_type = to_llir_type(dest.var.type)
        self.traverse(instr.src, builder)
        alloc = builder.alloca(llir_type)
        builder.store(ir.Constant(alloc.type.pointee, var), alloc)
      elif instr.operation == ops.MLIL_VAR_PHI:
        dest: bn.SSAVariable = instr.dest
        src: list[bn.SSAVariable] = instr.src
        llir_type = to_llir_type(dest.var.type)
        alloc = builder.alloca(llir_type)
        phi = builder.phi(to_llir_type(src[0].var.type))
      elif instr.operation == ops.MLIL_CONST:
        var = instr.constant
      elif instr.operation == ops.MLIL_GOTO:
        builder.branch(self.ir_basic_blocks[instr.dest][1])
      elif instr.operation == ops.MLIL_RET:
        # TODO: multiple returns, etc.
        builder.ret(ir.Constant(ir.IntType(instr.src[0].size * 8), instr.src[0].constant))
      else:
        pass
        #raise NotImplementedError(f'{str(instr.operation)} is not implemented')
    elif isinstance(instr, list):
      for entry in instr:
        self.traverse(entry, builder)
    else:
      print(f'<Not an operation, {type(instr)}, {str(instr)}>')
      raise ValueError


def translate_function_mlil(parser, func, ir_func):
  Traverser(parser, func.medium_level_il, ir_func)
