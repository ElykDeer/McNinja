from binaryninja import TypeClass
from llvmlite import ir
import warnings


def to_llir_type(bn_type):
  tc = bn_type.type_class

  if tc == TypeClass.VoidTypeClass:
    return ir.VoidType()

  elif tc == TypeClass.BoolTypeClass:
    return ir.IntType(bn_type.width * 8)

  elif tc == TypeClass.IntegerTypeClass:
    return ir.IntType(bn_type.width * 8)

  elif tc == TypeClass.FloatTypeClass:
    full_width = bn_type.width * 8
    if full_width == 16:
      return ir.HalfType()

    elif full_width == 32:
      return ir.FloatType()

    elif full_width == 64:
      return ir.DoubleType()
    warnings.warn("Float size not accounted for...")
    return None

  elif tc == TypeClass.StructureTypeClass:
    ir_members = []
    for member in bn_type.members():
      ir_members.append(to_llir_type(member))
    return ir.LiteralStructType(ir_members, packed=bn_type.packed())

  elif tc == TypeClass.EnumerationTypeClass:
    warnings.warn("Not sure if this is entirely correct...")
    return ir.IntType(bn_type.width * 8)

  elif tc == TypeClass.PointerTypeClass:
    # TODO: look into this? LLVM IR does not like void pointers...
    if bn_type.target.type_class == TypeClass.VoidTypeClass:
      return ir.PointerType(ir.IntType(bn_type.width * 8))
    return ir.PointerType(to_llir_type(bn_type.target))

  elif tc == TypeClass.ArrayTypeClass:
    return ir.ArrayType(to_llir_type(bn_type.element_type), bn_type.count)

  elif tc == TypeClass.FunctionTypeClass:
    return ir.FunctionType(to_llir_type(bn_type.return_value),
                           [to_llir_type(x.type) for x in bn_type.parameters])

  elif tc == TypeClass.VarArgsTypeClass:
    return ir.FunctionType(to_llir_type(bn_type.return_value),
                           [to_llir_type(x.type) for x in bn_type.parameters], var_arg=True)

  elif tc == TypeClass.ValueTypeClass:
    warnings.warn("ValueTypeClass not implemented...")
    return None

  elif tc == TypeClass.NamedTypeReferenceClass:
    warnings.warn("NamedTypeReferenceClass not implemented...")
    return None

  elif tc == TypeClass.WideCharTypeClass:
    warnings.warn("WideCharTypeClass not implemented")
    return None
