from llvmlite import ir
import binaryninja as bn
from binaryninja.mediumlevelil import MediumLevelILBasicBlock, MediumLevelILOperation as ops
from binaryninja.variable import Variable


from .type_translator import to_llir_type
from .helpers import recover_true_false_branches


class Traverser:
  def __init__(self, parser, func: bn.MediumLevelILFunction, ir_func: ir.Function):
    self.parser = parser
    self.function = func
    self.ir_function = ir_func

    self._il_to_ir_bb = {}
    # self._var_def_block = {}
    self._ir_var_defs = {}

  ###########
  # Helpers #
  ###########
  # def set_def_block_for_var(self, var: Variable, basic_block: MediumLevelILBasicBlock):
  #   self._var_def_block[var] = basic_block

  # def get_def_block_for_var(self, var: Variable) -> MediumLevelILBasicBlock:
  #   return self._var_def_block[var]

  def set_il_to_ir_block_mapping(self, il_block: MediumLevelILBasicBlock, ir_block: ir.IRBuilder):
    assert(isinstance(il_block, MediumLevelILBasicBlock))
    assert(isinstance(ir_block, ir.IRBuilder))
    self._il_to_ir_bb[il_block] = ir_block

  def get_ir_builder_for_il_block(self, il_block: MediumLevelILBasicBlock) -> ir.IRBuilder:
    assert(isinstance(il_block, MediumLevelILBasicBlock))
    if il_block in self._il_to_ir_bb:
      return self._il_to_ir_bb[il_block]
    return None

  def set_ir_var_def(self, var: Variable, definition: ir.Instruction):
    assert(isinstance(var, Variable))
    assert(isinstance(definition, ir.Instruction))
    self._ir_var_defs[var] = definition

  def get_ir_var_def(self, var: Variable) -> ir.Instruction:
    assert(isinstance(var, Variable))
    if var in self._ir_var_defs:
      return self._ir_var_defs[var]
    return None

  #############
  # Main body #
  #############
  def translate(self):
    # Declare each block ahead of time so recovering control flow is easier
    for il_block in self.function:
      ir_block = self.ir_function.append_basic_block(f'block-{il_block.index:x}')
      self.set_il_to_ir_block_mapping(il_block, ir.IRBuilder(ir_block))

    # TODO : Probably define aliases here too
    entry_block_builder = self.get_ir_builder_for_il_block(self.function.basic_blocks[0])
    for var in self.function.vars:
      self.set_ir_var_def(var, entry_block_builder.alloca(to_llir_type(var.type)))

    for il_block in self.function.basic_blocks:
      # print(f'{il_block.index}:{il_block}')
      for instr in il_block:
        self.traverse(instr, self.get_ir_builder_for_il_block(il_block))

  def traverse(self, instr: bn.MediumLevelILInstruction, builder: ir.IRBuilder):
    # TODO : Skip lines assigning deadstores
    # TODO : fold assignments, remove temporaries?

    if isinstance(instr, list):
      return [self.traverse(entry, builder) for entry in instr]
    elif not isinstance(instr, bn.mediumlevelil.MediumLevelILInstruction):
      # print(f'<Not an operation, {type(instr)}, {str(instr)}>')
      raise ValueError

    # print(f'  <MediumLevelILOperation, {str(instr.operation)}>')

    ###############################
    # Potentially recursive cases #
    ###############################

    ### MLIL_SET_VAR ###
    if ops.MLIL_SET_VAR == instr.operation:
      dest_var = self.get_ir_var_def(instr.dest)
      rhs_value = self.traverse(instr.src, builder)
      builder.store(rhs_value, dest_var)

    ### MLIL_GOTO ###
    elif ops.MLIL_GOTO == instr.operation:
      builder.branch(self.get_ir_builder_for_il_block(instr.il_basic_block.outgoing_edges[0].target).block)

    ### MLIL_RET ###
    elif ops.MLIL_RET == instr.operation:
      # TODO: multiple returns, etc.
      builder.ret(ir.Constant(ir.IntType(instr.src[0].size * 8), instr.src[0].constant))

    ### MLIL_CALL ###
    elif ops.MLIL_CALL == instr.operation:
      if instr.dest.operation == ops.MLIL_CONST_PTR:
        call_target = self.parser.functions[instr.dest.constant]
      else:
        raise NotImplementedError(f"Non-constant calls not yet implemented (`{instr.dest.operation}`)")

      new_args = [self.traverse(operand, builder) for operand in instr.params]
      builder.call(call_target, new_args)

    ### MLIL_IF ###
    elif ops.MLIL_IF == instr.operation:
      condition = self.traverse(instr.condition, builder)
      true_branch, false_branch = recover_true_false_branches(instr)
      builder.cbranch(condition,
                      self.get_ir_builder_for_il_block(true_branch).block,
                      self.get_ir_builder_for_il_block(false_branch).block)

    ##############
    # Base cases #
    ##############

    ### MLIL_VAR ###
    elif ops.MLIL_VAR == instr.operation:
      # TODO : Alignment might be wrong
      return builder.load(self.get_ir_var_def(instr.src), align=instr.src.type.width)

    ### MLIL_CONST ###
    elif ops.MLIL_CONST == instr.operation:
      return ir.Constant(ir.IntType(instr.size*8), instr.constant)

    ### MLIL_CONST_PTR ###
    elif ops.MLIL_CONST_PTR == instr.operation:
      return self.parser.global_vars[instr.constant].bitcast(ir.IntType(instr.expr_type.target.width*8).as_pointer())
      # var = self.parser.global_vars[instr.constant]
      # return ir.Constant(ir.IntType(instr.size*8), var).bitcast(ir.IntType(instr.size).as_pointer())

    ### MLIL_SUB ###
    elif ops.MLIL_SUB == instr.operation:
      return builder.sub(self.traverse(instr.left, builder), self.traverse(instr.right, builder))

    ### MLIL_CMP_NE ###
    elif ops.MLIL_CMP_NE == instr.operation:
      # TODO : not always an `icmp`...work that out later
      return builder.icmp_unsigned("!=", self.traverse(instr.left, builder), self.traverse(instr.right, builder))

    else:
      pass
      # raise NotImplementedError(f'{str(instr.operation)} is not implemented')
