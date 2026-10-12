#!/usr/bin/env bash
set -euo pipefail

# Locate zig (system PATH or local /tmp/py_zig install)
if command -v zig >/dev/null 2>&1; then
    ZIG="zig"
elif [ -x "/tmp/py_zig/ziglang/zig" ]; then
    ZIG="/tmp/py_zig/ziglang/zig"
else
    echo "[!] zig not found; install via: pip install --target /tmp/py_zig ziglang" >&2
    exit 1
fi

mkdir -p bin build_obj
rm -rf build_obj/*

echo "[*] Compiling MinHook v1.3.3 (x86-windows-gnu)..."
for f in vendor/minhook/src/buffer.c vendor/minhook/src/hook.c vendor/minhook/src/trampoline.c vendor/minhook/src/hde/hde32.c; do
    "$ZIG" cc -target x86-windows-gnu -O2 -Ivendor/minhook/include -Ivendor/minhook/src \
        -c "$f" -o "build_obj/$(basename "$f" .c).o"
done

echo "[*] Compiling Lua 5.4.6 (x86-windows-gnu)..."
for f in vendor/lua/*.c; do
    "$ZIG" cc -target x86-windows-gnu -O2 -Ivendor/lua \
        -c "$f" -o "build_obj/lua_$(basename "$f" .c).o"
done

echo "[*] Compiling Dear ImGui (x86-windows-gnu)..."
for f in vendor/imgui/*.cpp; do
    "$ZIG" c++ -target x86-windows-gnu -std=c++17 -O2 -Ivendor/imgui \
        -c "$f" -o "build_obj/$(basename "$f" .cpp).o"
done

echo "[*] Compiling NRTH DLL sources (x86-windows-gnu)..."
for f in nrth_config.cpp nrth_hook.cpp nrth_ui.cpp; do
    "$ZIG" c++ -target x86-windows-gnu -std=c++17 -O2 \
        -I. -Ivendor/minhook/include -Ivendor/imgui -Ivendor/lua \
        -c "$f" -o "build_obj/$(basename "$f" .cpp).o"
done

echo "[*] Linking bin/nvx.dll and publishing bin/NRTH.dll..."
"$ZIG" c++ -target x86-windows-gnu -shared -O2 -s \
    -Wl,--image-base,0x10000000 -Wl,--subsystem,console \
    build_obj/nrth_hook.o build_obj/nrth_config.o build_obj/nrth_ui.o \
    build_obj/buffer.o build_obj/hook.o build_obj/trampoline.o build_obj/hde32.o \
    build_obj/imgui*.o build_obj/lua_*.o \
    nrth_dll.def \
    -ld3d9 -luser32 -lgdi32 -ladvapi32 -lpsapi -ldwmapi \
    -o bin/nvx.dll
cp bin/nvx.dll bin/NRTH.dll

echo "[*] Building bin/NORTH LOADER.exe (x86-windows-gnu)..."
"$ZIG" c++ -target x86-windows-gnu -std=c++17 -O2 -s \
    -Wl,--subsystem,console \
    north_loader.cpp -ladvapi32 -luser32 -lpsapi \
    -o "bin/NORTH LOADER.exe"

echo "[*] Building bin/NRTH_audit.dll (x86-windows-gnu)..."
"$ZIG" c++ -target x86-windows-gnu -std=c++17 -shared -O2 -s \
    -Wl,--image-base,0x10000000 -Wl,--subsystem,console \
    -DNRTH_AUDIT_BUILD nrth_audit.cpp nrth_audit.def \
    -o bin/NRTH_audit.dll

rm -rf build_obj bin/*.lib bin/*.pdb
echo "[+] Build complete:"
sha256sum "bin/nvx.dll" "bin/NRTH.dll" "bin/NORTH LOADER.exe" "bin/NRTH_audit.dll"
