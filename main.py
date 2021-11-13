#!/usr/bin/env python3

from hlil_compiler.compiler import create_execution_engine, compile_ir
from hlil_compiler.helpers import global_string_constant

from llvmlite import ir
from ctypes import CFUNCTYPE, c_double


#################
# IR Generation #
#################


def basic_add_function_example():
  # Top level: Module
  module = ir.Module(name=__file__)

  # Just a function prototype, name, and module it belongs to
  func = ir.Function(module, ir.FunctionType(ir.DoubleType(), (ir.DoubleType(), ir.DoubleType())), name="fpadd")
  a, b = func.args

  # Functions have labeled basic blocks
  block = func.append_basic_block(name="entry")
  block_builder = ir.IRBuilder(block)  # An IR Builder is the internal rep

  # Add the instruction fadd, which has a return value
  result = block_builder.fadd(a, b, name="res")
  # Add an instruction to return the value returned from the last op
  block_builder.ret(result)

  return module


def call_external_function_example():
  module = ir.Module(name=__file__)

  # Just a function prototype, name, and module it belongs to
  func = ir.Function(module, ir.FunctionType(ir.VoidType(), []), name="main")

  # Functions have labeled basic blocks
  block = func.append_basic_block(name="entry")
  block_builder = ir.IRBuilder(block)  # An IR Builder is the internal rep

  # Declare printf
  printf = ir.Function(module, ir.FunctionType(ir.IntType(32), [ir.IntType(8).as_pointer()], var_arg=True), name="printf")

  # Create global string and get a reference to it
  string = global_string_constant(module, "Hello world!\n", "string_name_thing")

  # Convert the type from a string constant to a char*?
  format_string = block_builder.bitcast(string, ir.IntType(8).as_pointer())  # TODO : This is wrong.  I don't know how to do it right.

  # Call function
  block_builder.call(printf, [format_string])  # Tack more string into that list to use the var_args format string stuff

  # All functions need explicit returns
  block_builder.ret_void()

  return module


###################
# Compile/execute #
###################

if __name__ == "__main__":
  # A module represents a program
  # module = basic_add_function_example()
  module = call_external_function_example()

  print(f"LLVM IR:\n```\n{module}\n```\n\n")

  engine = create_execution_engine()
  mod = compile_ir(engine, str(module))

  # Look up the function pointer (a Python int)
  # func_ptr = engine.get_function_address("fpadd")
  func_ptr = engine.get_function_address("main")

  # Run the function via ctypes
  # cfunc = CFUNCTYPE(c_double, c_double, c_double)(func_ptr)
  # res = cfunc(1.0, 3.5)
  # print("fpadd(...) =", res)

  # Run the function via ctypes
  CFUNCTYPE(None)(func_ptr)()
