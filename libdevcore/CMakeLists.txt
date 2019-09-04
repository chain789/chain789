file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

add_library(devcore ${sources} ${headers})

target_include_directories(devcore PUBLIC ${Boost_INCLUDE_DIR})
target_link_libraries(devcore PRIVATE ethash::ethash)