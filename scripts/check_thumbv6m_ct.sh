#!/usr/bin/env bash
# Regression check for KyberSlash-class timing leaks (CWE-208) on targets
# without a hardware divider, using thumbv6m (Cortex-M0/M0+) as the canary.
#
# On such targets LLVM lowers integer division to the variable-time
# __aeabi_uidiv software routine, and may lower a branchless sign mask
# (`u += (u >> 15) & Q`) back into a secret-dependent compare-and-branch.
# This script emits the crate's thumbv6m assembly and asserts that the
# functions which touch secret coefficients on the decapsulation path
# contain neither.
#
# Poly::compress / PolyVec::compress legitimately contain ONE division on a
# *public* operand (LLVM's loop trip-count computation over the output slice
# length), so a single division call is tolerated there; the per-coefficient
# Compress_d loops themselves must stay division-free.
set -euo pipefail

cargo rustc --release --no-default-features --target thumbv6m-none-eabi -- --emit asm

ASM=$(ls target/thumbv6m-none-eabi/release/deps/kyber-*.s | head -1)
echo "Scanning $ASM"

fail=0

body() { # body <mangled-symbol-prefix>
    awk -v fn="^$1" '$0 ~ fn {f=1} f{print} f&&/\.fnend/{exit}' "$ASM"
}

check() { # check <mangled-symbol-prefix> <max-allowed-division-calls>
    local sym=$1 maxdiv=$2 b divs branches
    b=$(body "$sym")
    if [ -z "$b" ]; then
        echo "FAIL: symbol not found (renamed or optimized out?): $sym"
        fail=1
        return
    fi
    divs=$(printf '%s\n' "$b" | { grep -c "__aeabi_[a-z]*div" || true; })
    branches=$(printf '%s\n' "$b" | { grep -c "	bpl	\|	bmi	" || true; })
    echo "$sym: divisions=$divs (max $maxdiv), sign-branches=$branches"
    if [ "$divs" -gt "$maxdiv" ]; then
        echo "FAIL: $sym calls a variable-time software division routine"
        fail=1
    fi
    if [ "$branches" -ne 0 ]; then
        echo "FAIL: $sym branches on the sign of a (secret) coefficient"
        fail=1
    fi
}

# Decapsulation path: KyberSlash-1 (tomsg, inlined into indcpa::dec) and
# KyberSlash-2 (compress, reached via FO re-encryption in kem::decaps).
check _ZN5kyber6indcpa3dec 0
check _ZN5kyber6indcpa3enc 0
check _ZN5kyber3kem6decaps 0
check _ZN5kyber4poly4Poly8compress 1
check _ZN5kyber7polyvec7PolyVec8compress 1

if [ "$fail" -ne 0 ]; then
    echo "thumbv6m constant-time check FAILED"
    exit 1
fi
echo "thumbv6m constant-time check passed"
