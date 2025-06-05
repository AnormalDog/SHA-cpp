/**
 * Author: AnormalDog (https://github.com/AnormalDog)
 * Copyright (c) 2025 AnormalDog
 * Licensed under the MIT License. See LICENSE file in the project root for full license information.
*/

#include "SHA256/sha256.hpp"
#include <string>
#include <iostream>
#include <fstream>

std::string get_hash(const std::string& file_name);

int main(int argc, char** argv) {
  if (argc == 1) {
    std::cerr << "Atleast one file is required" << std::endl;
    return 1;
  }
  for (size_t i = 1; i < argc; ++i) {
    std::string file_name(argv[i]);
    std::cout << file_name << ": " << get_hash(file_name) << std::endl;
  }
  return 0;
}

std::string get_hash(const std::string& file_name) {
  std::ifstream file(file_name);
  if (file.is_open() == false) {
    file.close();
    return "file not found!";
  }
  std::string to_return = sha256::get_hash(file);
  file.close();
  return to_return;
}