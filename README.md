# SHA256
## Simple c++ library that calculate the sha256 hash of a input stream. 
### USAGE
- Include the sha256.hpp to your program and compile it. Doesn´t require any external library.
- Compile the sha256.cpp
- (or just check the CMakeLists.txt and modify/add them to fit your needs)
- Call it with sha256::get_hash(\<stream\>);
- The stream, due it uses the base class istream, can be neither a istream, a ifstream or a stringstream
- Returns a string with the hash in hex format
