add_library(SHA512 STATIC sha512.cpp)
target_include_directories(SHA512 PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_features(SHA512 PUBLIC cxx_std_20)
target_compile_options(SHA512 PUBLIC -O3)