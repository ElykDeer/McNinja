from llvmlite import ir
import binaryninja as bn

from .type_translator import to_llir_type
from .helpers import global_string_constant


def can_recurse(op):
  return


def resolve_variable(var_name, global_vars, local_vars):
  if var_name in local_vars:
    return local_vars[var_name]
  elif var_name in global_vars:
    return global_vars[var_name]
  else:
    raise ValueError("Requesting variable that doesn't exist")


def traverse_hlil_block(parser,
                        hlil_instr: bn.HighLevelILInstruction,
                        builder: ir.IRBuilder,
                        current_function_vars: dict,
                        current_args: list):
  ops = bn.highlevelil.HighLevelILOperation
  if isinstance(hlil_instr, bn.highlevelil.HighLevelILInstruction):
    print(f'  <HighLevelILOperation, {str(hlil_instr.operation)}>')

    if hlil_instr.operation == ops.HLIL_CALL_SSA:
      if hlil_instr.dest.operation == ops.HLIL_CONST_PTR:
        call_target = parser.functions[hlil_instr.dest.constant]
      else:
        raise NotImplementedError(f"Non-constant calls not yet implemented (`{hlil_instr.dest.operation}`)")

      # The idea here is that our children will populate our args, and we'll populate the current_args with our return value if we happen to be being called by a function
        # See the HLIL_CONST_PTR case
      new_args = []
      for operand in hlil_instr.params:
        traverse_hlil_block(parser, operand, builder, current_function_vars, new_args)

      builder.call(call_target, new_args)

    elif hlil_instr.operation == ops.HLIL_CONST_PTR:
      print(f'  <HLIL_CONST_PTR, {hex(hlil_instr.constant)}>')
      current_args.append(resolve_variable(hlil_instr.constant, parser.global_vars, current_function_vars).bitcast(ir.IntType(hlil_instr.size).as_pointer()))

    elif hlil_instr.operation == ops.HLIL_CONST:
      print(f'  <HLIL_CONST, {hex(hlil_instr.constant)}>')

    elif hlil_instr.operation == ops.HLIL_RET:
      # TODO : Ret operands
      builder.ret(ir.Constant(ir.IntType(hlil_instr.src[0].size*8), hlil_instr.src[0].constant))
      # for operand in hlil_instr.operands:
      #   traverse_il_block(parser, operand, builder, current_function_vars)

    else:
      raise NotImplementedError(f"`{ops[hlil_instr.operation]}` is not yet handled")

  elif isinstance(hlil_instr, list):
    for entry in hlil_instr:
      traverse_hlil_block(parser, entry, builder, current_function_vars, current_args)
  else:
    print(f'<Not an operation, {type(hlil_instr)}, {str(hlil_instr)}>')
    raise ValueError


# TODO : Parallelize block translation
def translate_function_hlil(parser, func, ir_func):
  function_locals = {}
  for bb in func.high_level_il.ssa_form:
    ir_bb = ir_func.append_basic_block()
    builder = ir.IRBuilder(ir_bb)
    for instr in bb:
      traverse_hlil_block(parser, instr, builder, function_locals, [])
