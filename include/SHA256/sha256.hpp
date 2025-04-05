/**
 * @file SHA256.hpp
 * @author AnormalDog
 * @brief 
 * @version 1.0
 * @date 2025-03-29
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef SHA256_HPP_
#define SHA256_HPP_

#include "SHA256/hash256.hpp"
#include <cstdint>
#include <iostream>

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
    uint32_t* group_block(const uint8_t* preprocess_block);

    uint32_t calculate_T1(const uint8_t iteration, const uint32_t* variables, const uint32_t* schedule);
    uint32_t calculate_T2(const uint8_t iteration, const uint32_t* variables, const uint32_t* schedule);
    uint32_t schedule_sigma(const uint8_t current_position, const uint32_t* schedule);

  }
  
  uint32_t* get_next_block(std::istream& is, bool& one_was_written, bool& finished_preprocess, uint64_t& total_bytes_readed);
  void compute_block(uint32_t* block, uint32_t* Hash256);

  Hash256 get_hash(std::istream& is);

}

/**
 * @brief Right rotation function
 * 
 * @param num 
 * @param rotations 
 * @return uint32_t 
 */
uint32_t sha256::functions::rrtr(const uint32_t num, const uint8_t rotations) {
  return ((num >> rotations) | (num << ((sizeof(uint32_t) * 8) - rotations)));
}

/**
 * @brief Sigma0 function in schedule
 * 
 * @param num 
 * @return uint32_t 
 */
uint32_t sha256::functions::schedule_sigma0(const uint32_t num) {
  return ((rrtr(num, 7)) ^ (rrtr(num, 18)) ^ (num >> 3));
}

/**
 * @brief Sigma1 function in schedule
 * 
 * @param num 
 * @return uint32_t 
 */
uint32_t sha256::functions::schedule_sigma1(const uint32_t num) {
  return ((rrtr(num, 17)) ^ (rrtr(num, 19)) ^ (num >> 10));
}

/**
 * @brief sigma0 function in hashing
 * 
 * @param num 
 * @return uint32_t 
 */
uint32_t sha256::functions::hashing_sigma0(const uint32_t num) {
  return ((rrtr(num, 2)) ^ (rrtr(num, 13)) ^ (rrtr(num, 22)));
}

/**
 * @brief sigma1 function in hashing
 * 
 * @param num 
 * @return uint32_t 
 */
uint32_t sha256::functions::hashing_sigma1(const uint32_t num) {
  return ((rrtr(num, 6)) ^ (rrtr(num, 11)) ^ (rrtr(num, 25)));
}

/**
 * @brief majority function
 * 
 * @param num1 
 * @param num2 
 * @param num3 
 * @return uint32_t 
 */
uint32_t sha256::functions::hashing_majority(const uint32_t num1, const uint32_t num2, const uint32_t num3) {
  // (num1 and num2) xor (num1 and num3) xor (num2 and num3)
  return ((num1 & num2) ^ (num1 & num3) ^ (num2 & num3));
}

/**
 * @brief choose function
 * 
 * @param num1 
 * @param num2 
 * @param num3 
 * @return uint32_t 
 */
uint32_t sha256::functions::hashing_choose(const uint32_t num1, const uint32_t num2, const uint32_t num3) {
  // (num1 and num2) xor ((not num1) and num3)
  return ((num1 & num2) ^ (~num1 & num3));
}

/**
 * @brief Group for bytes into a single uint32_t. Only works in little endian
 * 
 * @param num0 
 * @param num1 
 * @param num2 
 * @param num3 
 * @return uint32_t 
 */
uint32_t sha256::functions::group_bytes(const uint8_t num0, const uint8_t num1, const uint8_t num2, const uint8_t num3) {
  return (
    // Endianess sensible, only works on little endian
    // it suppose the num0 is the most significant number and num3 the less significant
    static_cast<uint32_t>(num0 << 24) | 
    static_cast<uint32_t>(num1 << 16) | 
    static_cast<uint32_t>(num2 << 8) | 
    static_cast<uint32_t>(num3 << 0)
  );
}

/**
 * @brief returns the zero padding of the block being processed
 * 
 * @param bytes_readed 
 * @return uint8_t 
 */
uint8_t sha256::functions::get_zero_padding(const uint8_t bytes_readed) {
  // 56 equal to 64 - sizeof(uint64_t)
  return (56 - bytes_readed);
}

/**
 * @brief append the bits readed at the end of the block
 * 
 * @param bytes_readed 
 * @param schedule 
 */
void sha256::functions::append_bytes_readed(const uint64_t bytes_readed, uint8_t* block) {
  block[63] = static_cast<uint8_t>((bytes_readed * 8));
  block[62] = static_cast<uint8_t>((bytes_readed * 8) >> 8);
  block[61] = static_cast<uint8_t>((bytes_readed * 8) >> 16);
  block[60] = static_cast<uint8_t>((bytes_readed * 8) >> 24);

  block[59] = static_cast<uint8_t>((bytes_readed * 8) >> 32);
  block[58] = static_cast<uint8_t>((bytes_readed * 8) >> 40);
  block[57] = static_cast<uint8_t>((bytes_readed * 8) >> 48);
  block[56] = static_cast<uint8_t>((bytes_readed * 8) >> 56);
}

/**
 * @brief apend the zeros to the proccesing block
 * 
 * @param zero_padding 
 * @param position 
 * @param schedule 
 */
void sha256::functions::append_zero_padding(const uint8_t zero_padding, const uint8_t position, uint8_t* schedule) {
  for (std::size_t i = 0; i < zero_padding; ++i) {
    if (position + i < 64) {
      schedule[position + i] = 0x00;
    }
  }
}

#endif