#!/usr/bin/env python3

from compiler import Parser
from compiler.compiler import create_execution_engine, compile_ir

import binaryninja
from ctypes import CFUNCTYPE

import platform

if platform.system() == "Windows":
  FILES = [
    "C:\\McNinja\\test_programs\\helloworld\\helloworld",
    "C:\\McNinja\\test_programs\\helloworld-for\\helloworld",
    "C:\\McNinja\\test_programs\\optimization-test\\optimization-test",
  ]
else:
  FILES = [
    "./test_programs/helloworld/helloworld",
    "./test_programs/helloworld-for/helloworld",
    "./test_programs/optimization-test/optimization-test",
  ]


def run_file(f):
  with binaryninja.open_view(f) as bv:
    bv.update_analysis_and_wait()

    parser = Parser(bv)

    parser.phase_1()
    parser.phase_2()
    parser.phase_3()

    module = parser.module

    print(f"LLVM IR:\n```\n{module}\n```\n\n")

    engine = create_execution_engine()
    mod = compile_ir(engine, str(module))

    # Look up the function pointer (a Python int)
    func_ptr = engine.get_function_address("main")

    # Run the function via ctypes
    CFUNCTYPE(None)(func_ptr)()


if __name__ == "__main__":
  for file in FILES:
    run_file(file)
