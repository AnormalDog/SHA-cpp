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

#include <array>
#include <cstdint>

namespace sha256 {
  namespace basic {
    constexpr std::array<uint32_t, 8> initial_hash_value {
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };
    
    constexpr std::array<uint32_t, 64> k_constants {
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

    inline uint32_t schedule_sigma0(const uint32_t num);
    inline uint32_t schedule_sigma1(const uint32_t num);

    inline uint32_t hashing_sigma0(const uint32_t num);
    inline uint32_t hashing_sigma1(const uint32_t num);
    inline uint32_t hashing_choose(const uint32_t num1, const uint32_t num2, const uint32_t num3);
    inline uint32_t hashing_majority(const uint32_t num1, const uint32_t num2, const uint32_t num3);
    
    inline uint32_t rrtr(const uint32_t num, const uint8_t roations);
  }
}

uint32_t sha256::basic::rrtr(const uint32_t num, const uint8_t rotations) {
  return ((num >> rotations) | (num << (sizeof(uint32_t) - rotations)));
}

uint32_t sha256::basic::schedule_sigma0(const uint32_t num) {
  return ((rrtr(num, 7)) ^ (rrtr(num, 18)) ^ (num >> 3));
}

uint32_t sha256::basic::schedule_sigma1(const uint32_t num) {
  return ((rrtr(num, 17)) ^ (rrtr(num, 19)) ^ (num >> 10));
}

uint32_t sha256::basic::hashing_sigma0(const uint32_t num) {
  return ((rrtr(num, 2)) ^ (rrtr(num, 13)) ^ (rrtr(num, 22)));
}

uint32_t sha256::basic::hashing_sigma1(const uint32_t num) {
  return ((rrtr(num, 6)) ^ (rrtr(num, 11)) ^ (rrtr(num, 25)));
}

uint32_t sha256::basic::hashing_majority(const uint32_t num1, const uint32_t num2, const uint32_t num3) {
  // (num1 and num2) xor (num1 and num3) xor (num2 and num3)
  return ((num1 & num2) ^ (num1 & num3) ^ (num2 & num3));
}

uint32_t sha256::basic::hashing_choose(const uint32_t num1, const uint32_t num2, const uint32_t num3) {
  // (num1 and num2) xor ((not num1) and num3)
  return ((num1 & num2) ^ (~num1 & num3));
}


#endif