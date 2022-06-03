import llvmlite.binding as llvm
from time import perf_counter

# All these initializations are required for code generation!
llvm.initialize()
llvm.initialize_native_target()
llvm.initialize_native_asmprinter()  # yes, even this one


def create_execution_engine():
  """
  Create an ExecutionEngine suitable for JIT code generation on
  the host CPU.  The engine is reusable for an arbitrary number of
  modules.
  """
  # Create a target machine representing the host
  target = llvm.Target.from_default_triple()
  target_machine = target.create_target_machine()
  # And an execution engine with an empty backing module
  backing_mod = llvm.parse_assembly("")
  engine = llvm.create_mcjit_compiler(backing_mod, target_machine)
  return engine


def optimize(mod, o_level, s_level):
  pmb = llvm.create_pass_manager_builder()
  pmb.opt_level = o_level
  pmb.size_level = s_level
  pm = llvm.create_module_pass_manager()
  pmb.populate(pm)

  t1 = perf_counter()
  pm.run(mod)
  t2 = perf_counter()
  print(f'Time to run optimizations at level {o_level}: {t2-t1:0.4f} seconds')
  print(f"Optimized LLVM IR:\n```\n{mod}\n```\n\n")


def compile_ir(engine, llvm_ir):
  """
  Compile the LLVM IR string with the given engine.
  The compiled module object is returned.
  """
  # Create a LLVM module object from the IR
  mod = llvm.parse_assembly(llvm_ir)
  mod.verify()

  optimize(mod, 3, 0)

  # Now add the module and make sure it is ready for execution
  engine.add_module(mod)
  engine.finalize_object()
  engine.run_static_constructors()
  return mod
