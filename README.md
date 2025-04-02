# SHA256
## Simple library that calculate the hash(sha256) of a stream

### USAGE
- Include (only is needed the sha256.hpp) to your program and compile it. Doesn´t require any external library.
- Call it with sha256::get_hash("stream");
- It returns a object of the type hash256, that can be converted to a hex string with the method get_hex();
