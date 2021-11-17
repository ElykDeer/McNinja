from llvmlite import ir
import binaryninja as bn
from binaryninja.mediumlevelil import MediumLevelILBasicBlock, MediumLevelILOperation as ops, SSAVariable

from .type_translator import to_llir_type
from .helpers import recover_true_false_branches


class Traverser:
  def __init__(self, parser, func: bn.MediumLevelILFunction, ir_func: ir.Function):
    self.parser = parser
    self.function = func
    self.ir_function = ir_func

    self._il_to_ir_bb = {}
    # self._ssa_var_def_block = {}
    self._ir_var_defs = {}

  ###########
  # Helpers #
  ###########
  # def set_def_block_for_ssa_var(self, ssa_var: SSAVariable, basic_block: MediumLevelILBasicBlock):
  #   self._ssa_var_def_block[ssa_var] = basic_block

  # def get_def_block_for_ssa_var(self, ssa_var: SSAVariable) -> MediumLevelILBasicBlock:
  #   return self._ssa_var_def_block[ssa_var]

  def set_il_to_ir_block_mapping(self, il_block: MediumLevelILBasicBlock, ir_block: ir.IRBuilder):
    assert(isinstance(il_block, MediumLevelILBasicBlock))
    assert(isinstance(ir_block, ir.IRBuilder))
    self._il_to_ir_bb[il_block] = ir_block

  def get_ir_builder_for_il_block(self, il_block: MediumLevelILBasicBlock) -> ir.IRBuilder:
    assert(isinstance(il_block, MediumLevelILBasicBlock))
    if il_block in self._il_to_ir_bb:
      return self._il_to_ir_bb[il_block]
    return None

  def set_ir_var_def(self, ssa_var: SSAVariable, definition: ir.Instruction):
    assert(isinstance(ssa_var, SSAVariable))
    assert(isinstance(definition, ir.Instruction))
    self._ir_var_defs[ssa_var] = definition

  def get_ir_var_def(self, ssa_var: SSAVariable) -> ir.Instruction:
    assert(isinstance(ssa_var, SSAVariable))
    if ssa_var in self._ir_var_defs:
      return self._ir_var_defs[ssa_var]
    return None

  #############
  # Main body #
  #############
  def translate(self):
    # entry_block = self.function.basic_blocks[0]
    # for ssa_var in self.function.ssa_form.ssa_vars:
    #   # TODO : Add this back
    #   # if not self.function.is_ssa_var_live(ssa_var):
    #   #   continue

    #   var_def = self.function.ssa_form.get_ssa_var_definition(ssa_var)
    #   if var_def is not None:
    #     self.set_def_block_for_ssa_var(ssa_var, var_def.il_basic_block)
    #   else:  # TODO : handle aliased vars
    #     self.set_def_block_for_ssa_var(ssa_var, entry_block)  # Variables that don't have defs are usually (see: aliased_vars) defined at entry

    # Declare each block ahead of time so recovering control flow is easier
    for il_block in self.function.ssa_form:
      ir_block = self.ir_function.append_basic_block(f'block-{il_block.index:x}')
      self.set_il_to_ir_block_mapping(il_block, ir.IRBuilder(ir_block))

    # Define version zeros at top of function
    # TODO : Probably define aliases here too
    entry_block_builder = self.get_ir_builder_for_il_block(self.function.ssa_form.basic_blocks[0])
    for ssa_var in self.function.ssa_form.ssa_vars:
      if ssa_var.version != 0:
        continue
      self.set_ir_var_def(ssa_var, entry_block_builder.alloca(to_llir_type(ssa_var.var.type)))

    for il_block in self.function.ssa_form.basic_blocks:
      print(f'{il_block.index}:{il_block}')
      for instr in il_block:
        self.traverse(instr, self.get_ir_builder_for_il_block(il_block))

    # Resolve PHIs now that we've constructed the places they come from
    for il_block in self.function.ssa_form.basic_blocks:
      for instr in il_block:
        self.resolve_phi(instr, self.get_ir_builder_for_il_block(il_block))

  def traverse(self, instr: bn.MediumLevelILInstruction, builder: ir.IRBuilder):
    # TODO : Skip lines assigning deadstores
    # TODO : fold assignments, remove temporaries?

    if isinstance(instr, list):
      return [self.traverse(entry, builder) for entry in instr]
    elif not isinstance(instr, bn.mediumlevelil.MediumLevelILInstruction):
      print(f'<Not an operation, {type(instr)}, {str(instr)}>')
      raise ValueError

    print(f'  <MediumLevelILOperation, {str(instr.operation)}>')
    ### MLIL_SET_VAR_SSA ###
    if ops.MLIL_SET_VAR_SSA == instr.operation:
      dest_var = self.get_ir_var_def(instr.dest)
      # TODO : Figure out this recursive call
      # var = self.traverse()

      if dest_var:
        builder.store(ir.Constant(dest_var.type.pointee, var), dest_var)
      else:
        self.set_ir_var_def(instr.dest, builder.alloca(to_llir_type(instr.dest.var.type)))

    ### MLIL_VAR_PHI ###
    elif ops.MLIL_VAR_PHI == instr.operation:
      dest_type = to_llir_type(instr.dest.var.type)
      phi = builder.phi(dest_type)
      self.set_ir_var_def(instr.dest, phi)

    ### MLIL_CONST ###
    elif ops.MLIL_CONST == instr.operation:
      return ir.Constant(ir.IntType(1), instr.constant)

    ### MLIL_GOTO ###
    elif ops.MLIL_GOTO == instr.operation:
      builder.branch(self.get_ir_builder_for_il_block(instr.il_basic_block.outgoing_edges[0].target).block)

    ### MLIL_RET ###
    elif ops.MLIL_RET == instr.operation:
      # TODO: multiple returns, etc.
      builder.ret(ir.Constant(ir.IntType(instr.src[0].size * 8), instr.src[0].constant))

    ### MLIL_IF ###
    elif ops.MLIL_IF == instr.operation:
      # TODO : Get this to work
      # condition = self.traverse(instr.condition, builder)
      condition = ir.Constant(ir.IntType(1), 1)
      true_branch, false_branch = recover_true_false_branches(instr)
      builder.cbranch(condition,
                      self.get_ir_builder_for_il_block(true_branch).block,
                      self.get_ir_builder_for_il_block(false_branch).block)

    else:
      pass
      # raise NotImplementedError(f'{str(instr.operation)} is not implemented')

  def resolve_phi(self, instr: bn.MediumLevelILInstruction, builder: ir.IRBuilder):
    if isinstance(instr, list):
      for entry in instr:
        self.traverse(entry, builder)
    elif not isinstance(instr, bn.mediumlevelil.MediumLevelILInstruction):
      print(f'<Not an operation, {type(instr)}, {str(instr)}>')
      raise ValueError

    if ops.MLIL_VAR_PHI == instr.operation:
      phi = self.get_ir_var_def(instr.dest)
      for ssa_var in instr.src:
        ir_var = self.get_ir_var_def(ssa_var)
        phi.add_incoming(ir_var, ir_var.parent)
