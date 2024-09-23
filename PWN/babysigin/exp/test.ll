; ModuleID = 'main.c'
source_filename = "main.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@fd = dso_local global i32 34952, align 4
@chr0 = dso_local global i32 128, align 4
@.str = private unnamed_addr constant [6 x i8] c"/flag\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @func1(i8* noundef %path) #0 {
entry:
  %retval = alloca i32, align 4
  %path.addr = alloca i8*, align 8
  store i8* %path, i8** %path.addr, align 8
  %0 = load i8*, i8** %path.addr, align 8
  call void @WMCTF_OPEN(i8* noundef %0, i32 noundef 0)
  %1 = load i32, i32* %retval, align 4
  ret i32 %1
}

declare void @WMCTF_OPEN(i8* noundef, i32 noundef) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @func2(i8* noundef %path) #0 {
entry:
  %retval = alloca i32, align 4
  %path.addr = alloca i8*, align 8
  store i8* %path, i8** %path.addr, align 8
  %0 = load i8*, i8** %path.addr, align 8
  %call = call i32 @func1(i8* noundef %0)
  %1 = load i32, i32* %retval, align 4
  ret i32 %1
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @func3(i8* noundef %path) #0 {
entry:
  %retval = alloca i32, align 4
  %path.addr = alloca i8*, align 8
  store i8* %path, i8** %path.addr, align 8
  %0 = load i8*, i8** %path.addr, align 8
  %call = call i32 @func2(i8* noundef %0)
  %1 = load i32, i32* %retval, align 4
  ret i32 %1
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @func4(i8* noundef %path) #0 {
entry:
  %retval = alloca i32, align 4
  %path.addr = alloca i8*, align 8
  store i8* %path, i8** %path.addr, align 8
  %0 = load i8*, i8** %path.addr, align 8
  %call = call i32 @func3(i8* noundef %0)
  %1 = load i32, i32* %retval, align 4
  ret i32 %1
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
entry:
  %retval = alloca i32, align 4
  %path = alloca i8*, align 8
  store i32 0, i32* %retval, align 4
  store i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str, i64 0, i64 0), i8** %path, align 8
  %0 = load i8*, i8** %path, align 8
  %call = call i32 @func4(i8* noundef %0)
  call void @WMCTF_MMAP(i32 noundef 30864)
  call void @WMCTF_READ(i32 noundef 26214)
  %1 = load i32, i32* @fd, align 4
  call void @WMCTF_WRITE(i32 noundef %1)
  ret i32 0
}

declare void @WMCTF_MMAP(i32 noundef) #1

declare void @WMCTF_READ(i32 noundef) #1

declare void @WMCTF_WRITE(i32 noundef) #1

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 1}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
