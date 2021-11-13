from llvmlite import ir


def translate_fucntion(bv, module, func, ir_func):
  for bb in func.high_level_il.ssa_form:
    ir_bb = ir_func.append_basic_block()
    builder = ir.IRBuilder(ir_bb)
