![sneakyburgers](img/mcninja.png)

Compiles BinaryNinja's HLIL to LLVM

## Approach
1. Sweep binary for global variables, create them
2. Sweep binary for (used?) external functions, declare those
3. Sweep binary for internal functions, translate them

## (Devdocs, sorta) Things to know about LLVM IR / LLVMLite

1. A program is a ir.Module; the entire program (at least for our simple test cases) can live in these modules
2. Analogous to BinaryNinja, a program consists of functions (ir.Function) with basic blocks (ir.IRBuilder)
3. Every basic block needs to end with a basic block terminator, which is one of: [ret, br, switch, indirectbr, invoke, callbr, resume, catchswitch, catchret, cleanupret, unreachable]
   - The consequence of this that we should probably process the body of all the basic blocks in a function, then do another pass to stitch them together.  Alternatively, we could create all the basic blocks at the beginning and patch them together as we go along.  Thankfully we already have a known BB layout, so solving this should be hard..it's just a design consideration.

## FAQ

### How do you pronounce McNinja and where did the name come from

This is a hotly contested issue. We must explore the etymology of the name to find an answer. The "Mc" in McNinja was originally a contraction of the words "Machine Code," and the "ninja" is short for "BinaryNinja."  It is possible that "MC" in that case is pronounced em-see. Alas, even those who understand the origin of the name pronounce it as if it were related to America's favorite fast food joint.


---

main.py has some examples of how to do some basic llvmlite IR construction
