#include "SHA256/sha256.hpp"
#include <sstream>
#include <iostream>
#include <iomanip>

int main() {
  std::string string ("jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj");
  std::stringstream stream(string);
  bool one_was_written = false;
  bool finished_preprocess = false;
  uint64_t bytes_written = 0;

  sha256::get_hash(stream);

  return 0;
}