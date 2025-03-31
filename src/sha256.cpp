/**
 * @file SHA256.cpp
 * @author AnormalDog
 * @brief 
 * @version 0.1
 * @date 2025-03-29
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "SHA256/sha256.hpp"
#include <fstream>
#include <cassert>
#include <iostream>

namespace sha256 {
  namespace constants {
    const uint32_t initial_hash_value[8] {
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    const uint32_t k_constants[64] {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
  }
}

uint32_t sha256::schedule_sigma(const uint8_t current_position, const uint32_t* schedule) {
  assert(current_position >= 0 && current_position < 64);
  if (current_position >= 0 && current_position < 16) {
    return schedule[current_position];
  }
  const uint32_t aux0 = functions::schedule_sigma1(schedule[current_position - 2]);
  const uint32_t aux1 = schedule[current_position - 7];
  const uint32_t aux2 = functions::schedule_sigma0(schedule[current_position - 15]);
  const uint32_t aux3 = schedule[current_position - 16];
  return (aux0 + aux1 + aux2 + aux3);
}

std::array<uint32_t, 16> sha256::get_next_block(std::istream& is, bool& one_was_written, bool& finished_preprocess, uint64_t& total_bytes_readed) {
  uint8_t readed_bytes[64];
  is.read(reinterpret_cast<char*>(readed_bytes), 64);
  uint64_t bytes_readed = static_cast<uint64_t>(is.gcount());
  total_bytes_readed += bytes_readed;

  if (bytes_readed <= 55) {
    if (one_was_written == false) {
      readed_bytes[bytes_readed] = 0x80;
      bytes_readed += 1;
      one_was_written = true;
    }
    functions::append_zero_padding(functions::get_zero_padding(bytes_readed), bytes_readed, readed_bytes);
    functions::append_bytes_readed(total_bytes_readed, readed_bytes);
    finished_preprocess = true;
  }
  else if (bytes_readed > 55 && bytes_readed < 64) {
    if (one_was_written == false) {
      readed_bytes[bytes_readed] = 0x80;
      bytes_readed += 1;
      one_was_written = true;
    }
    functions::append_zero_padding(functions::get_zero_padding(bytes_readed), bytes_readed, readed_bytes);
  }
  unsigned a = 0;
  while (a < 64) {
    std::cout << std::hex << std::setfill('0') << std::setw(2) << +readed_bytes[a];
    std::cout << std::hex << std::setfill('0') << std::setw(2) << +readed_bytes[a+1];
    std::cout << std::hex << std::setfill('0') << std::setw(2) << +readed_bytes[a+2];
    std::cout << std::hex << std::setfill('0') << std::setw(2) << +readed_bytes[a+3];
    std::cout << std::endl;
    a += 4;
  }
  return functions::group_block(readed_bytes);
}

std::array<uint32_t, 16> sha256::functions::group_block(const uint8_t* block) {
  uint8_t aux = 0;
  std::array<uint32_t, 16> to_return;
  while (aux < 64) {
    const uint32_t row = group_bytes(block[aux], block[aux + 1], block[aux + 2], block[aux + 3]);
    to_return[(aux / 4)] = row;
    aux += 4;
  }
  return to_return;
}