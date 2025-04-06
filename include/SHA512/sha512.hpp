/**
 * @file sha512.hpp
 * @author AnormalDog
 * @brief 
 * @version 0.1
 * @date 2025-04-06
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef SHA512_HPP_
#define SHA512_HPP_

#include <cstdint>
#include <iostream>
#include <string>

namespace sha512 {
  namespace constants {
    extern const uint64_t k_constants[80];
  }
  namespace functions {
    inline uint16_t get_zero_padding(const uint16_t bytes_readed);
  }
}


uint16_t sha512::functions::get_zero_padding(const uint16_t bytes_readed) {
  return (112 - bytes_readed);
}

#endif