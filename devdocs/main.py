#!/usr/bin/env python3

from compiler.compiler import create_execution_engine, compile_ir
from compiler.helpers import global_string_constant

from llvmlite import ir
from ctypes import CFUNCTYPE, c_double


#################
# IR Generation #
#################


# The most basic example of a function that takes two values, adds them, and returns the result
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


# The most simple example that calls an external: hello world!
def call_external_function_example():
  # A program is a ir.Module
  module = ir.Module(name=__file__)

  # Phase 1, declare globals
  # Create global string and get a reference to it
  string = global_string_constant(module, "Hello world!\n", "string_name_thing")

  # Phase 2, declare needed externs
  # Declare printf
  printf = ir.Function(module, ir.FunctionType(ir.IntType(32), [ir.IntType(8).as_pointer()], var_arg=True), name="printf")
  # TODO : This generates a function prototype with default variable names, which we can manually patch out if we overwrite the args again after this line

  # Phase 3, the actual function body

  # Just a function prototype, name, and module it belongs to
  func = ir.Function(module, ir.FunctionType(ir.VoidType(), []), name="main")

  # Functions have labeled basic blocks
  block = func.append_basic_block(name="entry")
  block_builder = ir.IRBuilder(block)  # An IR Builder is the internal rep

  # Convert the type from a string constant to a char*?
  format_string = block_builder.bitcast(string, ir.IntType(8).as_pointer())  # TODO : This is wrong.  I don't know how to do it right.

  # Call function
  block_builder.call(printf, [format_string])  # Tack more string into that list to use the var_args format string stuff

  # All functions need explicit returns
  block_builder.ret_void()

  return module


# The most simple example of a function with multiple BBs
def multiple_basic_blocks_example():
  # A program is a ir.Module
  module = ir.Module(name=__file__)

  # Phase 1, declare globals
  # Create global string and get a reference to it
  string = global_string_constant(module, "Hello world!\n", "string_name_thing")

  # Phase 2, declare needed externs
  # Declare printf
  printf = ir.Function(module, ir.FunctionType(ir.IntType(32), [ir.IntType(8).as_pointer()], var_arg=True), name="printf")

  # Phase 3, the actual function body
  # Just a function prototype, name, and module it belongs to
  func = ir.Function(module, ir.FunctionType(ir.VoidType(), []), name="main")

  def basic_block_1():
    # Functions have labeled basic blocks
    block = func.append_basic_block(name="bb1")
    block_builder = ir.IRBuilder(block)  # An IR Builder is the internal rep

    # Convert the type from a string constant to a char*?
    format_string = block_builder.bitcast(string, ir.IntType(8).as_pointer())  # TODO : This is wrong.  I don't know how to do it right.

    # Call function
    block_builder.call(printf, [format_string])  # Tack more string into that list to use the var_args format string stuff

    # This block needs to have a terminator....we'll need to know the BB destination in order to finalize this BB
    return block_builder

  def basic_block_2():
    # Functions have labeled basic blocks
    block = func.append_basic_block(name="bb2")
    block_builder = ir.IRBuilder(block)  # An IR Builder is the internal rep

    # Convert the type from a string constant to a char*?
    format_string = block_builder.bitcast(string, ir.IntType(8).as_pointer())  # TODO : This is wrong.  I don't know how to do it right.

    # Call function
    block_builder.call(printf, [format_string])  # Tack more string into that list to use the var_args format string stuff
    return block_builder

  bb1 = basic_block_1()
  bb2 = basic_block_2()

  # All functions need explicit returns
  bb1.branch(bb2.block)
  bb2.ret_void()

  return module


###################
# Compile/execute #
###################
if __name__ == "__main__":
  #############
  # Example 1 #
  #############
  print("############################################# Example 1 Start #############################################")
  # A module represents a program
  module = basic_add_function_example()

  print(f"LLVM IR:\n```\n{module}\n```\n\n")

  engine = create_execution_engine()
  mod = compile_ir(engine, str(module))

  # Look up the function pointer (a Python int)
  func_ptr = engine.get_function_address("fpadd")

  # Run the function via ctypes
  cfunc = CFUNCTYPE(c_double, c_double, c_double)(func_ptr)
  res = cfunc(1.0, 3.5)
  print("fpadd(...) =", res)

  #############
  # Example 2 #
  #############
  print("############################################# Example 2 Start #############################################")
  # A module represents a program
  module = call_external_function_example()

  print(f"LLVM IR:\n```\n{module}\n```\n\n")

  engine = create_execution_engine()
  mod = compile_ir(engine, str(module))

  # Look up the function pointer (a Python int)
  func_ptr = engine.get_function_address("main")

  # Run the function via ctypes
  CFUNCTYPE(None)(func_ptr)()

  #############
  # Example 3 #
  #############
  print("############################################# Example 3 Start #############################################")
  # A module represents a program
  module = multiple_basic_blocks_example()

  print(f"LLVM IR:\n```\n{module}\n```\n\n")

  engine = create_execution_engine()
  mod = compile_ir(engine, str(module))

  # Look up the function pointer (a Python int)
  func_ptr = engine.get_function_address("main")

  # Run the function via ctypes
  CFUNCTYPE(None)(func_ptr)()
