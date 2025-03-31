#include "SHA256/sha256.hpp"
#include <sstream>
#include <iostream>
#include <iomanip>

int main() {
  std::string string ("aaaaa");
  std::stringstream stream(string);
  bool one_was_written = false;
  bool finished_preprocess = false;
  uint64_t bytes_written = 0;

  std::array<uint32_t, 16> block = sha256::get_next_block(stream, one_was_written, finished_preprocess, bytes_written);

  /*
  std::cout << std::hex << std::setfill('0');
  for (size_t i = 0; i < block.size(); ++i) {
    std::cout << std::setw(8) << block[i] << std::endl;
  }
*/

  return 0;
}