/**
 * @file Hash256.hpp
 * @author AnormalDog
 * @brief class for returning the Hash256
 * @version 1.0
 * @date 2025-04-01
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef Hash256_HPP_
#define Hash256_HPP_

#include <cstdint>
#include <array>
#include <string>

/**
 * @brief class that represent an abstraction of a hash256
 * 
 */
class Hash256 {
  public:
    Hash256();
    Hash256(const uint32_t* array);
    Hash256(const Hash256& Hash256);
    ~Hash256();

    std::string get_hex() const;

    Hash256& operator=(const Hash256& Hash256);
  private:
    std::array<uint32_t, 8> Hash256_;
};

#endif