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
    self.ssa_vars = {}
    self.ir_vars = {}

    last_var_def = None
    for ssa_var in func.ssa_form.ssa_vars:
      var_def = func.ssa_form.get_ssa_var_definition(ssa_var)
      if var_def is not None:
        last_var_def = var_def
        self.ssa_vars[ssa_var] = var_def.il_basic_block
      else:
        self.ssa_vars[ssa_var] = last_var_def.il_basic_block

    for bb in func.ssa_form:
      ir_block = self.ir_function.append_basic_block(f'{bb.index:x}')
      self.ir_basic_blocks.append((ir.IRBuilder(ir_block), ir_block))

    for var, block in self.ssa_vars.items():
      # Store all ssa vars in the first block because we are cool.
      builder, block = self.ir_basic_blocks[0]
      self.ir_vars[var] = builder.alloca(to_llir_type(var.var.type))

    for block in self.basic_blocks:
      print(f'{block.index}:{block}')
      for instr in block:
        self.traverse(instr, self.ir_basic_blocks[block.index][0])

  def find_block(self, index):
    for bb in self.basic_blocks:
      if bb.start <= index <= bb.end:
        return self.ir_basic_blocks[bb.index][1]

  def traverse(self, instr: bn.MediumLevelILInstruction, builder: ir.IRBuilder, var=None):
    ops = bn.mediumlevelil.MediumLevelILOperation
    if isinstance(instr, bn.mediumlevelil.MediumLevelILInstruction):
      print(f'  <MediumLevelILOperation, {str(instr.operation)}>')
      if instr.operation == ops.MLIL_SET_VAR_SSA:
        dest_var = self.ir_vars[instr.dest]
        self.traverse(instr.src, builder)
        builder.store(ir.Constant(dest_var.type.pointee, var), dest_var)
      elif instr.operation == ops.MLIL_VAR_PHI:
        real_dest = self.ir_vars[instr.dest]
        real_src = [self.ir_vars[var] for var in instr.src]
        phi = builder.phi(real_src[0].type.pointee)
        for ssa_var in real_src:
          block = None
          for tests, cool_block in self.ssa_vars.items():
            if self.ir_vars[tests] == ssa_var:
              block = cool_block
              break
          phi.add_incoming(builder.load(ssa_var), self.ir_basic_blocks[block.index][1])
          builder.store(phi, real_dest)
      elif instr.operation == ops.MLIL_CONST:
        var = instr.constant
      elif instr.operation == ops.MLIL_GOTO:
        builder.branch(self.find_block(instr.dest))
      elif instr.operation == ops.MLIL_RET:
        # TODO: multiple returns, etc.
        builder.ret(ir.Constant(ir.IntType(instr.src[0].size * 8), instr.src[0].constant))
      elif instr.operation == ops.MLIL_IF:
        print(instr.operands)
        self.traverse(instr.condition, builder)
        # TODO: Grab var from traversal
        var = ir.Constant(ir.IntType(1), 1)
        with builder.if_else(var) as (then, otherwise):
          with then:
            builder.branch(self.find_block(instr.true))
          with otherwise:
            builder.branch(self.find_block(instr.false))
        builder.ret(ir.Constant(ir.IntType(32), 0))
      else:
        pass
        # raise NotImplementedError(f'{str(instr.operation)} is not implemented')
    elif isinstance(instr, list):
      for entry in instr:
        self.traverse(entry, builder)
    else:
      print(f'<Not an operation, {type(instr)}, {str(instr)}>')
      raise ValueError


def translate_function_mlil(parser, func, ir_func):
  Traverser(parser, func.medium_level_il, ir_func)
