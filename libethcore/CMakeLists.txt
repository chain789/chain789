file(GLOB sources "*.cpp" "*.h")

add_library(ethcore ${sources})
target_link_libraries(ethcore PUBLIC devcrypto devcore)

include_directories(
        ${CMAKE_SOURCE_DIR}
        )