/**
 * @file SHA256.hpp
 * @author AnormalDog
 * @brief 
 * @version 0.1
 * @date 2025-03-29
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef SHA256_HPP_
#define SHA256_HPP_

#include <cstdint>
#include <iostream>
#include <array>

#include <iomanip>

namespace sha256 {
  namespace constants {
    extern const uint32_t initial_hash_value[8];
    extern const uint32_t k_constants[64];
  }
  namespace functions {

    inline uint32_t schedule_sigma0(const uint32_t num);
    inline uint32_t schedule_sigma1(const uint32_t num);

    inline uint32_t hashing_sigma0(const uint32_t num);
    inline uint32_t hashing_sigma1(const uint32_t num);
    inline uint32_t hashing_choose(const uint32_t num1, const uint32_t num2, const uint32_t num3);
    inline uint32_t hashing_majority(const uint32_t num1, const uint32_t num2, const uint32_t num3);
    
    inline uint32_t rrtr(const uint32_t num, const uint8_t roations);

    inline uint32_t group_bytes(const uint8_t num0, const uint8_t num1, const uint8_t num2, const uint8_t num3);
    inline uint8_t get_zero_padding(const uint8_t bytes_readed);
    inline void append_bytes_readed(const uint64_t bytes_readed, uint8_t* schedule);
    inline void append_zero_padding(const uint8_t zero_padding, const uint8_t position, uint8_t* schedule);
    std::array<uint32_t, 16> group_block(const uint8_t* preprocess_block);
  }
  
  uint32_t schedule_sigma(const uint8_t current_position, const uint32_t* schedule);

  std::array<uint32_t, 16> get_next_block(std::istream& is, bool& one_was_written, bool& finished_preprocess, uint64_t& total_bytes_readed);

}

uint32_t sha256::functions::rrtr(const uint32_t num, const uint8_t rotations) {
  return ((num >> rotations) | (num << ((sizeof(uint32_t) * 8) - rotations)));
}

uint32_t sha256::functions::schedule_sigma0(const uint32_t num) {
  return ((rrtr(num, 7)) ^ (rrtr(num, 18)) ^ (num >> 3));
}

uint32_t sha256::functions::schedule_sigma1(const uint32_t num) {
  return ((rrtr(num, 17)) ^ (rrtr(num, 19)) ^ (num >> 10));
}

uint32_t sha256::functions::hashing_sigma0(const uint32_t num) {
  return ((rrtr(num, 2)) ^ (rrtr(num, 13)) ^ (rrtr(num, 22)));
}

uint32_t sha256::functions::hashing_sigma1(const uint32_t num) {
  return ((rrtr(num, 6)) ^ (rrtr(num, 11)) ^ (rrtr(num, 25)));
}

uint32_t sha256::functions::hashing_majority(const uint32_t num1, const uint32_t num2, const uint32_t num3) {
  // (num1 and num2) xor (num1 and num3) xor (num2 and num3)
  return ((num1 & num2) ^ (num1 & num3) ^ (num2 & num3));
}

uint32_t sha256::functions::hashing_choose(const uint32_t num1, const uint32_t num2, const uint32_t num3) {
  // (num1 and num2) xor ((not num1) and num3)
  return ((num1 & num2) ^ (~num1 & num3));
}

uint32_t sha256::functions::group_bytes(const uint8_t num0, const uint8_t num1, const uint8_t num2, const uint8_t num3) {
  return (
    static_cast<uint32_t>(num0 << 24) | 
    static_cast<uint32_t>(num1 << 16) | 
    static_cast<uint32_t>(num2 << 8) | 
    static_cast<uint32_t>(num3 << 0)
  );
}

uint8_t sha256::functions::get_zero_padding(const uint8_t bytes_readed) {
  // 56 equal to 64 - sizeof(uint64_t)
  return (56 - bytes_readed);
}

void sha256::functions::append_bytes_readed(const uint64_t bytes_readed, uint8_t* schedule) {
  schedule[63] = static_cast<uint8_t>(bytes_readed);
  schedule[62] = static_cast<uint8_t>(bytes_readed >> 8);
  schedule[61] = static_cast<uint8_t>(bytes_readed >> 16);
  schedule[60] = static_cast<uint8_t>(bytes_readed >> 24);

  schedule[59] = static_cast<uint8_t>(bytes_readed >> 32);
  schedule[58] = static_cast<uint8_t>(bytes_readed >> 40);
  schedule[57] = static_cast<uint8_t>(bytes_readed >> 48);
  schedule[56] = static_cast<uint8_t>(bytes_readed >> 56);
}

void sha256::functions::append_zero_padding(const uint8_t zero_padding, const uint8_t position, uint8_t* schedule) {
  for (std::size_t i = 0; i < zero_padding; ++i) {
    schedule[position + i] = 0x00;
  }
}

#endif