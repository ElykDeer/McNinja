from binaryninja import Type, TypeClass, NamedTypeReferenceType, BinaryView
from typing import Optional
from llvmlite import ir
import warnings


def to_llir_type(bn_type: Type, bv: Optional[BinaryView] = None):
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
      ir_members.append(to_llir_type(member, bv))
    return ir.LiteralStructType(ir_members, packed=bn_type.packed())

  elif tc == TypeClass.EnumerationTypeClass:
    warnings.warn("Not sure if this is entirely correct...")
    return ir.IntType(bn_type.width * 8)

  elif tc == TypeClass.PointerTypeClass:
    # TODO: look into this? LLVM IR does not like void pointers...
    if bn_type.target.type_class == TypeClass.VoidTypeClass:
      return ir.PointerType(ir.IntType(bn_type.width * 8))
    return ir.PointerType(to_llir_type(bn_type.target, bv))

  elif tc == TypeClass.ArrayTypeClass:
    return ir.ArrayType(to_llir_type(bn_type.element_type, bv), bn_type.count)

  elif tc == TypeClass.FunctionTypeClass:
    return ir.FunctionType(to_llir_type(bn_type.return_value, bv),
                           [to_llir_type(x.type, bv) for x in bn_type.parameters],
                           var_arg=bn_type.has_variable_arguments.value)

  elif tc == TypeClass.VarArgsTypeClass:
    return ir.FunctionType(to_llir_type(bn_type.return_value, bv),
                           [to_llir_type(x.type, bv) for x in bn_type.parameters], var_arg=True)

  elif tc == TypeClass.ValueTypeClass:
    raise NotImplementedError('ValueTypeClass not implemented')

  elif tc == TypeClass.NamedTypeReferenceClass:
    # TODO: fix this, for some reason a NamedTypeReference to a size_t stores no information regarding the type
    if bn_type.name == 'size_t':
      return ir.IntType(64)
    raise NotImplementedError('NamedTypeReferenceClass not implemented')

  elif tc == TypeClass.WideCharTypeClass:
    raise NotImplementedError('WideCharTypeClass not implemented')
