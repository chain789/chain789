cmake_minimum_required(VERSION 3.0)
project(my-sgx-sign)

set(SGX_ARCH x64)
# set SDK path
if (DEFINED ENV{SGX_SDK})
    set(SGX_SDK $ENV{SGX_SDK})
else()
    set(SGX_SDK /opt/intel/sgxsdk)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH} )

set(SGX_MODE SIM)
set(SGX_BUILD DEBUG)

include(cmake/ConfigSGX.cmake)

set(ProjectDir ${CMAKE_SOURCE_DIR})
set(MBEDTLS_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Enclave/mbedtls-SGX)

# Boost
set(Boost_USE_STATIC_LIBS ON)
set(Boost_DIR "${CMAKE_SOURCE_DIR}/3rd_party/lib/cmake/Boost")
set(BOOST_ROOT "${CMAKE_SOURCE_DIR}/3rd_party")
find_package(Boost 1.65.1 CONFIG REQUIRED COMPONENTS program_options filesystem system)
message(status " [Boost_LIBRARIES] ${Boost_LIBRARIES}")
message(status " [Boost_INCLUDE_DIRS] ${Boost_INCLUDE_DIRS}")
message(status " [Boost_DIR] ${Boost_DIR}")

set(ethash_DIR	"${CMAKE_SOURCE_DIR}/3rd_party/lib/cmake/ethash")
set(ETHASH_ROOT "${CMAKE_SOURCE_DIR}/3rd_party")
find_package(ethash CONFIG REQUIRED)

set(deps_prefix "${CMAKE_SOURCE_DIR}/3rd_party")
set(SECP256K1_LIBRARY "${deps_prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}secp256k1${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(SECP256K1_INCLUDE_DIR "${deps_prefix}/include")

# create imported library
add_library(Secp256k1 STATIC IMPORTED)
file(MAKE_DIRECTORY "${SECP256K1_INCLUDE_DIR}")
set_property(TARGET Secp256k1 PROPERTY IMPORTED_CONFIGURATIONS Release)
set_property(TARGET Secp256k1 PROPERTY IMPORTED_LOCATION_RELEASE "${SECP256K1_LIBRARY}")
set_property(TARGET Secp256k1 PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${SECP256K1_INCLUDE_DIR}")

add_subdirectory(libdevcore)
add_subdirectory(libdevcrypto)
add_subdirectory(libethcore)
add_subdirectory(libethereum)

add_subdirectory(App)
add_subdirectory(Enclave)