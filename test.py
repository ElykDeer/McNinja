#!/usr/bin/env python3

# This file iterates through all the programs in the test_programs folder, doing the following:
#  1. Executes the original binary file and records its output
#  2. Analyzes the binary file, emits LLVM bitcode, recompiles that bitcode, executes the recompiled bitcode, and saves the output of that
#  3. Compares the two results, prints both results if they're not exactly the same

import os
import sys
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
  class Capturing(list):
    def __enter__(self):
      self._stdout = sys.stdout
      sys.stdout = self._stringio = StringIO()
      return self

    def __exit__(self, *args):
      self.extend(self._stringio.getvalue())
      del self._stringio    # free up some memory
      sys.stdout = self._stdout

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

    # Run the function via ctypes
    with Capturing() as output:
      CFUNCTYPE(None)(func_ptr)()

    return output


def run_tests():
  passed = 0
  total = 0
  for test, filename in get_binary_files():
    total += 1
    print(f"[TESTING - {test}] Starting test `{test}`.")
    try:
      print(f"[TESTING - {test}] Executing file `{filename}`)...", end="", flush=True)
      original_output = execute_file(filename)
      print("done")
    except:
      print(f"[ERROR] Failed to execute `{filename}`")

    try:
      print(f"[TESTING - {test}] Recompiling and executing file `{filename}`)...", end="", flush=True)
      recompiled_output = recompile_and_execute_file(filename)
      print("done")
    except:
      print(f"[ERROR] Failed to recompile and execute `{filename}`")

    if original_output == recompiled_output:
      passed += 1
      print(f"[TESTING - {test}] Passed!")
    else:
      print(f"[TESTING - {test}] Failed")
      print(f"[TESTING - {test}] Original output:")
      for line in original_output.splitlines():
        print(f"[TESTING - {test}]  {line}")
      print(f"[TESTING - {test}] Recompiled output:")
      for line in recompiled_output.splitlines():
        print(f"[TESTING - {test}]  {line}")
      # TODO : Pretty print differences

  if passed == total:
    print(f"PASSED ({passed}/{total})")
  else:
    print(f"FAILED! ({passed}/{total})")


if __name__ == '__main__':
  run_tests()
