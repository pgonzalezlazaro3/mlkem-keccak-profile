#!/usr/bin/env bash
# Builds liboqs 0.16.0 twice and runs bench_mlkem.c against each build.
#
#   portable  : ML-KEM in portable C, Keccak in portable C
#   optimised : ML-KEM arithmetic in NEON (Arm) or AVX2 (x86), Keccak unchanged
#
# Keccak is the same portable C code in both builds, so comparing them shows
# what happens to Keccak's share once the rest of ML-KEM is accelerated.
#
# Needs: git, cmake, ninja, a C compiler, python3. Takes a few minutes.
set -euo pipefail
cd "$(dirname "$0")"

LIBOQS_VERSION=0.16.0
ALGS="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024"

for tool in git cmake ninja cc python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing: $tool. See the README, section Setup." >&2
        exit 1
    fi
done

if [ ! -d liboqs ]; then
    echo "== Downloading liboqs $LIBOQS_VERSION"
    git clone --quiet --depth 1 --branch "$LIBOQS_VERSION" https://github.com/open-quantum-safe/liboqs.git liboqs
fi

COMMON=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF "-DOQS_MINIMAL_BUILD=$ALGS")

NO_NATIVE_MLKEM=()
for p in 512 768 1024; do
    NO_NATIVE_MLKEM+=("-DOQS_ENABLE_KEM_ml_kem_${p}_aarch64=OFF" "-DOQS_ENABLE_KEM_ml_kem_${p}_x86_64=OFF")
done

echo "== Building liboqs, portable"
cmake -S liboqs -B build/portable "${COMMON[@]}" "${NO_NATIVE_MLKEM[@]}" --log-level=WARNING -Wno-dev
cmake --build build/portable

echo "== Building liboqs, optimised"
cmake -S liboqs -B build/optimised "${COMMON[@]}" --log-level=WARNING -Wno-dev
cmake --build build/optimised

mkdir -p results
for b in portable optimised; do
    echo "== Compiling bench_mlkem.c against the $b build"
    cc -O2 -Wall -Wextra -Ibuild/$b/include bench_mlkem.c build/$b/lib/liboqs.a -o "bench_$b"
done

{
    echo "Date: $(date '+%Y-%m-%d %H:%M')"
    echo "liboqs: $LIBOQS_VERSION"
    echo "OS: $(uname -sr)"
    echo "Machine: $(uname -m)"
    if command -v sysctl >/dev/null 2>&1; then
        echo "CPU: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
    fi
    echo "Compiler: $(cc --version | head -n 1)"
} > results/system.txt

echo "== Running (close other apps and keep the laptop plugged in)"
./bench_portable portable results/portable.csv
./bench_optimised optimised results/optimised.csv

python3 summarize.py
