import binaryninja as bn
import warnings
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
    if tc == bn.TypeClass.VoidTypeClass:
        return ir.VoidType()
    elif tc == bn.TypeClass.BoolTypeClass:
        return ir.IntType(bn_type.width * 8)
    elif tc == bn.TypeClass.IntegerTypeClass:
        return ir.IntType(bn_type.width * 8)
    elif tc == bn.TypeClass.FloatTypeClass:
        full_width = bn_type.width * 8
        if full_width == 16:
            return ir.HalfType()
        elif full_width == 32:
            return ir.FloatType()
        elif full_width == 64:
            return ir.DoubleType()
        warnings.warn("Float size not accounted for...")
        return None
    elif tc == bn.TypeClass.StructureTypeClass:
        ir_members = []
        for member in bn_type.members():
            ir_members.append(to_llvm_ir_type(member))
        return ir.LiteralStructType(ir_members, packed=bn_type.packed())
    elif tc == bn.TypeClass.EnumerationTypeClass:
        warnings.warn("Not sure if this is entirely correct...")
        return ir.IntType(bn_type.width)
    elif tc == bn.TypeClass.PointerTypeClass:
        return ir.PointerType(to_llvm_ir_type(bn_type.target))
    elif tc == bn.TypeClass.ArrayTypeClass:
        return ir.ArrayType(to_llvm_ir_type(bn_type.element_type()), bn_type.count())
    elif tc == bn.TypeClass.FunctionTypeClass:
        return ir.FunctionType(to_llvm_ir_type(bn_type.return_value), [to_llvm_ir_type(x.type) for x in bn_type.parameters])
    elif tc == bn.TypeClass.VarArgsTypeClass:
        return ir.FunctionType(to_llvm_ir_type(bn_type.return_value), [to_llvm_ir_type(x.type) for x in bn_type.parameters], var_arg=True)
    elif tc == bn.TypeClass.ValueTypeClass:
        warnings.warn("ValueTypeClass not implemented...")
        return None
    elif tc == bn.TypeClass.NamedTypeReferenceClass:
        warnings.warn("NamedTypeReferenceClass not implemented...")
        return None
    elif tc == bn.TypeClass.WideCharTypeClass:
        warnings.warn("WideCharTypeClass not implemented")
        return None

with bn.open_view("C:\\users\\admin\\downloads\\helloworld") as bv:
    bv.update_analysis_and_wait()
    function = None
    for func in bv.functions:
        if "main" in func.name:
            function = func
            break

    ir_module = ir.Module()

    ir_fun_type = to_llvm_ir_type(function.function_type)
    ir_fun = ir.Function(ir_module, ir_fun_type, name=function.name)

    for block in function.high_level_il.ssa_form:
        ir_block = ir_fun.append_basic_block()
        builder = ir.IRBuilder(ir_block)
        #for instr in block:
        #    print(instr)

    print(ir_module)