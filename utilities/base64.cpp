//  Copyright 2021 Sébastian Dejonghe
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#include <stdexcept>

#include <utilities/base64.h>

//    aaaaaa bbbbbb cccccc dddddd
//    xxxxxx xxyyyy yyyyzz zzzzzz
// 1) aaaaaa ffgggg hhhhii dddddd
// 2) aaaaaa ffgggg hhhh00
// 3) aaaaaa ff0000

std::string BinaryToUrlBase64(std::string_view value) {
  static char const* const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";

  size_t const size = value.size();

  std::string result;
  result.reserve(((size + 2) / 3) * 4);

  uint8_t const* end = (uint8_t const*)value.data() + size;

  for (uint8_t const* current_block = (uint8_t const*)value.data(); current_block < end; current_block += 3) {
    int const count = end - current_block;

    char b64_block[4];

    int const x = (int)current_block[0];

    b64_block[0] = table[x >> 2];

    int const f = (x & 0x3) << 4;

    int blocks;

    if (count > 1) {
      int const y = (int)current_block[1];

      int const g = y >> 4;

      b64_block[1] = table[f | g];

      int const h = (y & 0xf) << 2;

      if (count > 2) {
        int const z = (int)current_block[2];

        int const i = z >> 6;

        b64_block[2] = table[h | i];

        int const d = z & 0x3f;

        b64_block[3] = table[d];

        blocks = 4;
      } else {
        b64_block[2] = table[h];

        blocks = 3;
      }
    } else {
      b64_block[1] = table[f];

      blocks = 2;
    }

    result.append(b64_block, blocks);
  }

  return result;
}

std::string UrlBase64ToBinary(std::string_view value) {
  static int8_t const table[] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                 -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, 52, 53, 54, 55,
                                 56, 57, 58, 59, 60, 61, -1, -1, -1, 64, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
                                 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, -1, 26, 27, 28, 29, 30, 31, 32,
                                 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};

  size_t const size = value.size();

  std::string result;
  result.reserve(((size + 3) / 4) * 3);

  char const* end = value.data() + size;

  for (char const* current_block = value.data(); current_block < end; current_block += 4) {
    int const count = end - current_block;

    char b256_block[3];

    int blocks;

    int const a = (int)table[current_block[0]];

    if (count > 1) {
      int const b = (int)table[current_block[1]];

      int const f = b >> 4;

      b256_block[0] = (a << 2) | f;

      int const g = (b & 0xf) << 4;

      if (count > 2) {
        int const c = (int)table[current_block[2]];

        int const h = c >> 2;

        b256_block[1] = g | h;

        int const i = (c & 3) << 6;

        if (count > 3) {
          int const d = (int)table[current_block[3]];

          b256_block[2] = i | d;

          blocks = 3;
        } else {
          // cas 2.

          if (i) {
            // Les bits à droite (i) doivent être à 0.
            goto invalid_base64;
          }

          blocks = 2;
        }
      } else {
        // cas 3.

        if (g) {
          // Les bits à droite (g) doivent être à 0.
          goto invalid_base64;
        }

        blocks = 1;
      }
    } else {
      // Il faut au moins deux blocs.

      goto invalid_base64;
    }

    result.append(b256_block, blocks);
  }

  return result;

invalid_base64:
  throw std::runtime_error("Invalid base64 data");
}
