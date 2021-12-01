# Dev Docs

### Testing

Testing is provided by `./test.py`.  We analyze, emit LLVM, recompile the bitcode, and then compare the output of the new program to the output of the original program.

Simply run the file to test the current performance.

### main.py

Provides some examples of how to use llvmlite in some extremely basic use-cases

### Things to know about LLVM IR / LLVMLite

1. A program is a ir.Module; the entire program (at least for our simple test cases) can live in these modules
2. Analogous to BinaryNinja, a program consists of functions (ir.Function) with basic blocks (ir.IRBuilder)
3. Every basic block needs to end with a basic block terminator, which is one of: [ret, br, switch, indirectbr, invoke, callbr, resume, catchswitch, catchret, cleanupret, unreachable]
   - The consequence of this that we should probably process the body of all the basic blocks in a function, then do another pass to stitch them together.  Alternatively, we could create all the basic blocks at the beginning and patch them together as we go along.  Thankfully we already have a known BB layout, so solving this should be hard..it's just a design consideration.