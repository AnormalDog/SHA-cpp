add_executable(MAIN main.cpp)
target_include_directories(MAIN PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_features(MAIN PUBLIC cxx_std_20)

target_link_libraries(MAIN SHA256)