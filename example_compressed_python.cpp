// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// A fuzz target that consumes a Zlib-compressed input.
// This test verifies that we can find this bug with a custom mutator.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <zlib.h>

// The fuzz target.
// Uncompress the data, crash on input starting with "FU".
// Good luck finding this w/o a custom mutator. :)
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  uint8_t Uncompressed[100];
  size_t UncompressedLen = sizeof(Uncompressed);
  if (Z_OK != uncompress(Uncompressed, &UncompressedLen, Data, Size))
    return 0;
  if (UncompressedLen < 2) return 0;
#ifndef BENCHMARK
  if (Uncompressed[0] == 'F' && Uncompressed[1] == 'U')
    abort();  // Boom
#endif
  return 0;
}

#ifdef CUSTOM_MUTATOR

#include "python_bridge.cpp"

#endif // CUSTOM_MUTATOR
