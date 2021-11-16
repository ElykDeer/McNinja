; ModuleID = 'optimization-test.c'
source_filename = "optimization-test.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [11 x i8] c"value: %i\0A\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca i32*, align 8
  store i32 0, i32* %1, align 4
  %3 = call i8* @malloc(i64 4)
  %4 = ptrtoint i8* %3 to i64
  %5 = xor i64 %4, 4096
  %6 = inttoptr i64 %5 to i32*
  store i32* %6, i32** %2, align 8
  %7 = load i32*, i32** %2, align 8
  %8 = ptrtoint i32* %7 to i64
  %9 = xor i64 %8, 4096
  %10 = inttoptr i64 %9 to i32*
  store i32 100, i32* %10, align 4
  %11 = load i32*, i32** %2, align 8
  %12 = ptrtoint i32* %11 to i64
  %13 = xor i64 %12, 4096
  %14 = inttoptr i64 %13 to i32*
  %15 = load i32, i32* %14, align 4
  %16 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([11 x i8], [11 x i8]* @.str, i64 0, i64 0), i32 %15)
  %17 = load i32*, i32** %2, align 8
  %18 = ptrtoint i32* %17 to i64
  %19 = xor i64 %18, 4096
  %20 = inttoptr i64 %19 to i32*
  %21 = load i32, i32* %20, align 4
  ret i32 %21
}

declare dso_local i8* @malloc(i64) #1

declare dso_local i32 @printf(i8*, ...) #1

attributes #0 = { noinline nounwind optnone uwtable "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"Ubuntu clang version 12.0.0-3ubuntu1~21.04.2"}
