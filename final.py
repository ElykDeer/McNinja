#!/usr/bin/env python3

from hlil_compiler import Parser
from hlil_compiler.compiler import create_execution_engine, compile_ir

import binaryninja
from ctypes import CFUNCTYPE

###################
# Compile/execute #
###################
if __name__ == "__main__":
  print(1)
  with binaryninja.open_view("./test_programs/helloworld/helloworld") as bv:
    bv.update_analysis_and_wait()
    print(2)

    print(3)
    parser = Parser(bv)
    print(4)

    parser.phase_1()
    print(5)
    parser.phase_2()
    print(6)
    parser.phase_3()
    print(7)

    module = parser.module

    print(f"LLVM IR:\n```\n{module}\n```\n\n")

    engine = create_execution_engine()
    mod = compile_ir(engine, str(module))

    # Look up the function pointer (a Python int)
    func_ptr = engine.get_function_address("main")

    # Run the function via ctypes
    CFUNCTYPE(None)(func_ptr)()
