#!/bin/sh
# Build woofer_counter.exe (x64 + x86) via zig cc — same toolchain as the
# suite rebuild. Output: woofer_counter/bin/woofer_counter_{x64,x86}.exe
set -e
cd "$(dirname "$0")"
ZIG="${ZIG:-/tmp/py_zig/ziglang/zig}"
[ -x "$ZIG" ] || ZIG=$(command -v zig)
mkdir -p bin

CFLAGS="-s -O2 -Wall -Wextra -Wno-unused-parameter -Wl,--subsystem,console"
# NOTE: Crypt* (base CryptoAPI) resolves via advapi32 in zig's mingw — no
# separate -lcrypt32 needed (these exports live in advapi32.dll on Windows).
LIBS="-ladvapi32 -liphlpapi -luser32 -lshell32 -lpsapi -lntdll"

echo "== x64 =="
"$ZIG" cc $CFLAGS -target x86_64-windows-gnu woofer_counter.c -o bin/woofer_counter_x64.exe $LIBS

echo "== x86 =="
"$ZIG" cc $CFLAGS -target x86-windows-gnu woofer_counter.c -o bin/woofer_counter_x86.exe $LIBS

ls -l bin/
sha256sum bin/woofer_counter_x64.exe bin/woofer_counter_x86.exe
