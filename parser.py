import binaryninja as bn
from llvmlite import ir


def traverse_il_block(il, builder):
    if isinstance(il, bn.highlevelil.HighLevelILInstruction):
        print(il.operation.name)
        for o in il.operands:
            traverse_il_block(il, builder)

    else:
        print(f'ELSE: {type(il)}, {str(il)}')


def to_llvm_ir_type(bn_type):
    tc = bn_type.type_class
    if tc == bn.TypeClass.IntegerTypeClass:
        return ir.IntType(bn_type.width * 8)
    elif tc == bn.TypeClass.PointerTypeClass:
        return ir.PointerType(to_llvm_ir_type(bn_type.target))
    elif tc == bn.TypeClass.BoolTypeClass:
        return ir.IntType(bn_type.width * 8)


with bn.open_view("C:\\users\\admin\\downloads\\helloworld") as bv:
    bv.update_analysis_and_wait()
    function = None
    for func in bv.functions:
        if "main" in func.name:
            function = func
            break

    ir_module = ir.Module()

    fn_type = function.function_type
    ir_fun_type = \
        ir.FunctionType(to_llvm_ir_type(fn_type.return_value), [to_llvm_ir_type(x.type) for x in fn_type.parameters])
    ir_fun = ir.Function(ir_module, ir_fun_type, name=function.name)

    for block in function.high_level_il.ssa_form:
        ir_block = ir_fun.append_basic_block()
        builder = ir.IRBuilder(ir_block)
        #for instr in block:
        #    print(instr)

    print(ir_module)