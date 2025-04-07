/**
 * @file SHA256.cpp
 * @author AnormalDog
 * @brief 
 * @version 1.0
 * @date 2025-03-29
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "SHA256/sha256.hpp"
#include <cassert>
#include <iostream>
#include <iomanip>

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

/**
 * @brief Calculate the sigma in the schedule part
 * 
 * @param current_position 
 * @param schedule 
 * @return uint32_t 
 */
uint32_t sha256::functions::schedule_sigma(const uint8_t current_position, const uint32_t* schedule) {
  assert(current_position >= 0 && current_position < 64);
  if (current_position >= 0 && current_position < 16) {
    return schedule[current_position];
  }
  const uint32_t aux0 = schedule_sigma1(schedule[current_position - 2]);
  const uint32_t aux1 = schedule[current_position - 7];
  const uint32_t aux2 = schedule_sigma0(schedule[current_position - 15]);
  const uint32_t aux3 = schedule[current_position - 16];
  return (aux0 + aux1 + aux2 + aux3);
}

/**
 * @brief Returns a pointer to an array, who is the next processed block
 * 
 * @param is 
 * @param one_was_written 
 * @param finished_preprocess 
 * @param total_bytes_readed 
 * @return uint32_t* 
 */
uint32_t* sha256::functions::get_next_block(std::istream& is, bool& one_was_written, bool& finished_preprocess, uint64_t& total_bytes_readed) {
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

  return functions::group_block(readed_bytes);
}

/**
 * @brief group the uint8_t[64] block into uint8_t[16] block
 * 
 * @param block 
 * @return uint32_t* 
 */
uint32_t* sha256::functions::group_block(const uint8_t* block) {
  uint8_t aux = 0;
  uint32_t* to_return = new uint32_t[16];
  while (aux < 64) {
    const uint32_t row = group_bytes(block[aux], block[aux + 1], block[aux + 2], block[aux + 3]);
    to_return[(aux / 4)] = row;
    aux += 4;
  }
  return to_return;
}

/**
 * @brief Compute the current block
 * 
 * @param block 
 * @param hash 
 */
void sha256::functions::compute_block(uint32_t* block, uint32_t* hash) {
  uint32_t* schedule = new uint32_t[64];
  // Calculate schedule
  for (size_t i = 0; i < 64; ++i) {
    if (i < 16) {
      schedule[i] = block[i];
    }
    else {
      schedule[i] = functions::schedule_sigma(i, schedule);
    }
  }

  // Calculate intermediate hash part
  uint32_t* temporal_hash = new uint32_t[8];
  for (std::size_t i = 0; i < 8; ++i) {
    temporal_hash[i] = hash[i];
  }
  
  for (size_t i = 0; i < 64; ++i) {
    uint32_t T1 = functions::calculate_T1(i, temporal_hash, schedule);
    uint32_t T2 = functions::calculate_T2(i, temporal_hash, schedule);
    temporal_hash[7] = temporal_hash[6];
    temporal_hash[6] = temporal_hash[5];
    temporal_hash[5] = temporal_hash[4];
    temporal_hash[4] = (temporal_hash[3] + T1);
    temporal_hash[3] = temporal_hash[2];
    temporal_hash[2] = temporal_hash[1];
    temporal_hash[1] = temporal_hash[0];
    temporal_hash[0] = (T1 + T2);
  }
  for (size_t i = 0; i < 8; ++i) {
    hash[i] = temporal_hash[i] + hash[i];
  }

  // Free allocated memory
  delete[] temporal_hash;
  delete[] schedule;
}

/**
 * @brief Calculate temp1
 * 
 * @param iteration 
 * @param variables 
 * @param schedule 
 * @return uint32_t 
 */
uint32_t sha256::functions::calculate_T1(const uint8_t iteration, const uint32_t* variables, const uint32_t* schedule) {
  const uint32_t aux0 = variables[7];
  const uint32_t aux1 = hashing_sigma1(variables[4]);
  const uint32_t aux2 = hashing_choose(variables[4], variables[5], variables[6]);
  const uint32_t aux3 = constants::k_constants[iteration];
  const uint32_t aux4 = schedule[iteration];
  return (aux0 + aux1 + aux2 + aux3 + aux4);
}

/**
 * @brief Calculate temp2
 * 
 * @param iteration 
 * @param variables 
 * @param schedule 
 * @return uint32_t 
 */
uint32_t sha256::functions::calculate_T2(const uint8_t iteration, const uint32_t* variables, const uint32_t* schedule) {
  const uint32_t aux0 = hashing_sigma0(variables[0]);
  const uint32_t aux1 = hashing_majority(variables[0], variables[1], variables[2]);
  return (aux0 + aux1);
}

/**
 * @brief Returns a hash256 object, that contains the hash of the buffer
 * 
 * @param is 
 * @return Hash256 
*/
std::string sha256::get_hash(std::istream& is) {
  uint32_t* hash = new uint32_t[8];
  for (size_t i = 0; i < 8; ++i) {
    hash[i] = constants::initial_hash_value[i];
  }

  uint64_t bytes_readed = 0;
  bool one_was_written = false;
  bool finished_preprocess = false;
  
  uint32_t* block_pointer = nullptr;
  while (finished_preprocess == false) {
    block_pointer = functions::get_next_block(is, one_was_written, finished_preprocess, bytes_readed);
    functions::compute_block(block_pointer, hash);

    delete[] block_pointer;
    block_pointer = nullptr;
  }
  std::string to_return = functions::get_hex(hash);

  delete[] hash;
  return to_return;
}

/**
 * @brief return the sha256 in hex format
 * 
 * @param hash 
 * @return std::string 
 */
std::string sha256::functions::get_hex(const uint32_t* hash) {
  std::stringstream stream;
  stream << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < 8; ++i) {
    stream << std::setw(8) << hash[i];
  }
  return stream.str();
}