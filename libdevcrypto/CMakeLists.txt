file(GLOB SOURCES "*.cpp")
file(GLOB HEADERS "*.h")

add_library(devcrypto ${SOURCES} ${HEADERS})
target_link_libraries(devcrypto PUBLIC devcore Secp256k1)
include_directories(
        ../App
        ${CMAKE_SOURCE_DIR}
        ${SGXSDK_INCLUDE_DIRS}
        ${MBEDTLS_LIB_DIR}/include
        )