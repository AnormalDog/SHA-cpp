add_executable(TEST test.cpp)
target_include_directories(TEST PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(TEST PUBLIC cxx_std_20)
target_link_libraries(TEST SHA256)