from llvmlite import ir
import binaryninja as bn


def global_string_constant(module, string: str, name: str):
  c_fmt = ir.Constant(ir.ArrayType(ir.IntType(8), len(string)),
                      bytearray(string.encode("utf8")))
  global_fmt = ir.GlobalVariable(module, c_fmt.type, name)
  global_fmt.linkage = 'internal'
  global_fmt.global_constant = True
  global_fmt.initializer = c_fmt
  return global_fmt


def recover_true_false_branches(instr: bn.mediumlevelil.MediumLevelILInstruction) -> tuple[bn.mediumlevelil.MediumLevelILBasicBlock, bn.mediumlevelil.MediumLevelILBasicBlock]:
  true_branch = None
  false_branch = None
  for target in instr.il_basic_block.outgoing_edges:
    if target.type == bn.enums.BranchType.TrueBranch:
      true_branch = target.target
    elif target.type == bn.enums.BranchType.FalseBranch:
      false_branch = target.target
  return (true_branch, false_branch)
