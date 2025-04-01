#include "SHA256/sha256.hpp"
#include "SHA256/hash256.hpp"
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>

int main() {
  std::string string ("jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj");
  std::stringstream stream(string);

  std::ifstream file_in("image1.jpg");


  Hash256 aux = sha256::get_hash(file_in);
  std::cout << aux.get_hex() << std::endl;

  file_in.close();
  return 0;
}