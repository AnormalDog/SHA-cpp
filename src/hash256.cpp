/**
 * @file Hash256.cpp
 * @author AnormalDog
 * @brief 
 * @version 0.1
 * @date 2025-04-01
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#include "SHA256/hash256.hpp"
#include <sstream>
#include <iomanip>

Hash256::Hash256() {
  for (auto& iter : Hash256_) {
    iter = 0x0000;
  }
}

Hash256::Hash256(const uint32_t* array) {
  for (std::size_t i = 0; i < 8; ++i) {
    Hash256_[i] = array[i];
  }
}

Hash256::Hash256(const Hash256& Hash256) {
  Hash256_ = Hash256.Hash256_;
}

Hash256::~Hash256() {}

Hash256& Hash256::operator=(const Hash256& Hash256) {
  Hash256_ = Hash256.Hash256_;
  return *this;
}

std::string Hash256::get_hex() const {
  std::stringstream stream;
  stream << std::hex << std::setfill('0');
  for (const auto& iter : Hash256_) {
    stream << std::setw(8) << iter;
  }
  return stream.str();
}
