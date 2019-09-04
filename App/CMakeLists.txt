set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} -fPIC -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS} -std=c++11")

set(APP_SRC_FILES Enclave_u.c mbedtls_sgx_net.c utils.cpp)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_u.c
        COMMAND ${SGX_EDGER8R} --untrusted ${ProjectDir}/Enclave/Enclave.edl
        --search-path ${ProjectDir}/Enclave
        --search-path ${SGX_SDK}/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "Enclave_u.c; Enclave_u.h")

add_executable(a.out main.cpp ${APP_SRC_FILES})

add_executable(keygen keygen.cpp utils.cpp Enclave_u.c mbedtls_sgx_net.c)


include_directories(
        ${Boost_INCLUDE_DIRS}
        ${SGXSDK_INCLUDE_DIRS}
        ../
        ${MBEDTLS_LIB_DIR}/include)
      
target_link_libraries(a.out
        ethereum
        ${Boost_LIBRARIES}
        ${SGX_URTS_LIBRARY} ${SGX_USVC_LIBRARY}
        -lpthread -ldl)
target_link_libraries(keygen
        ${Boost_LIBRARIES} ${SGX_URTS_LIBRARY} ${SGX_USVC_LIBRARY} -lpthread -ldl)

add_dependencies(a.out enclave)
add_dependencies(keygen enclave)