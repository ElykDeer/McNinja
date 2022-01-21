#!/usr/bin/env python3

# This file iterates through all the programs in the test_programs folder, doing the following:
#  1. Executes the original binary file and records its output
#  2. Analyzes the binary file, emits LLVM bitcode, recompiles that bitcode, executes the recompiled bitcode, and saves the output of that
#  3. Compares the two results, prints both results if they're not exactly the same

import os
import sys
import select
import platform
from io import StringIO
import binaryninja as bn
from typing import List, Tuple
from subprocess import Popen, PIPE

from ctypes import CFUNCTYPE
from compiler import Parser
from compiler.compiler import create_execution_engine, compile_ir


# TODO : Relative imports for windows?
if platform.system() == "Windows":
  TEST_PROGRAMS = "C:\\McNinja\\test_programs\\"
  ORACLE_FILE = "C:\\McNinja\\oracle.json"
else:
  TEST_PROGRAMS = "./test_programs/"
  ORACLE_FILE = "./oracle.json"


def get_binary_files() -> List[Tuple[str, str]]:
  result = []
  for subdir, _, files in os.walk(TEST_PROGRAMS):
    for file in files:
      filename = os.path.join(subdir, file)
      if os.access(filename, os.X_OK):
        result.append((os.path.basename(subdir), filename))
  return result


def execute_file(file: str) -> str:
  process = Popen([file], stdout=PIPE)
  (output, _) = process.communicate()
  process.wait()
  return output.decode()


def recompile_and_execute_file(file):
  with bn.open_view(file) as bv:
    bv.update_analysis_and_wait()

    parser = Parser(bv)
    parser.phase_1()
    parser.phase_2()
    parser.phase_3()

    module = parser.module

  engine = create_execution_engine()
  mod = compile_ir(engine, str(module))

  # Look up the function pointer (a Python int)
  func_ptr = engine.get_function_address("main")

  # Run the function via ctypes and capture output
  pipe_out, pipe_in = os.pipe()
  stdout = os.dup(1)
  os.dup2(pipe_in, 1)
  os.close(pipe_in)

  CFUNCTYPE(None)(func_ptr)()

  output = ''
  while True:
    buffer = os.read(pipe_out, 1024)
    if not buffer:
      break
    output += str(buffer)

  os.close(1)
  os.close(pipe_out)
  os.dup2(stdout, 1)
  os.close(stdout)
  return output


def run_tests():
  passed = 0
  total = 0
  for test, filename in get_binary_files():
    total += 1
    print(f"[TESTING - {test}] Starting test `{test}`.")

    # # Run the original binary, get output
    # try:
    #   print(f"[TESTING - {test}] Executing file `{filename}`)...", end="", flush=True)
    #   original_output = execute_file(filename)
    #   print("done")
    # except:
    #   print(f"[ERROR] Failed to execute `{filename}`")

    # Run the recompiled binary, get output
    try:
      print(f"[TESTING - {test}] Recompiling and executing file `{filename}`)...", end="", flush=True)
      recompiled_output = recompile_and_execute_file(filename)
      print(recompiled_output)
      print("done")
    except:
      print(f"[ERROR] Failed to recompile and execute `{filename}`")

    # # Check if outputs are equal
    # if original_output == recompiled_output:
    #   passed += 1
    #   print(f"[TESTING - {test}] Passed!")
    # else:
    #   # If they're not equal, pretty print how they're not equal
    #   print(f"[TESTING - {test}] Failed")
    #   print("##################")
    #   print("Original output:")
    #   for line_n, line in enumerate(str(original_output).splitlines()):
    #     print(f"Line {line_n}:  {line}")
    #   print("##################")
    #   print("Recompiled output:")
    #   for line_n, line in enumerate(str(recompiled_output).splitlines()):
    #     print(f"Line {line_n}:  {line}")
    #   # TODO : Pretty print differences

    print()

  if passed == total:
    print(f"PASSED ({passed}/{total})")
  else:
    print(f"FAILED! ({passed}/{total})")


if __name__ == '__main__':
  run_tests()
