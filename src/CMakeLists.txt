add_library(SHA256 STATIC sha256.cpp)
target_include_directories(SHA256 PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_features(SHA256 PUBLIC cxx_std_20)
target_compile_options(SHA256 PUBLIC -O3)
