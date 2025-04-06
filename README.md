# 
## Simple c++ library that calculate the sha hash of a input stream. 
### USAGE
- Include the sha256.hpp to your program and compile it. Doesn´t require any external library.
- Compile the sha256.cpp
- (or just check the CMakeLists.txt and modify/add them to fit your needs)
- Call it with sha256::get_hash(\<stream\>);
- The stream, due it uses the base class std::istream, can be neither a std::istream, a std::ifstream or a std::stringstream
- Returns a string with the hash in hex format (big endian)
