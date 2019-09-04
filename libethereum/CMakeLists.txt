file(GLOB sources "*.cpp" "*.h")

add_library(ethereum ${sources})
target_link_libraries(ethereum ethcore devcrypto devcore)

include_directories(
        ${CMAKE_SOURCE_DIR}
        )