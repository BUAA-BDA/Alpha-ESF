cmake_minimum_required(VERSION 3.0)

project(henc)

enable_testing()

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose)

include_directories(${PROJECT_SOURCE_DIR}/include)

SET(CMAKE_BUILD_TYPE "Debug")
#SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O3 -Wall")

set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

aux_source_directory(${PROJECT_SOURCE_DIR}/src SRC_DIR_SRCS)

# static librray
ADD_LIBRARY(henc STATIC ${SRC_DIR_SRCS})
# shared library
add_library(alianhenc SHARED ${SRC_DIR_SRCS})

set_target_properties(alianhenc PROPERTIES OUTPUT_NAME "henc")
set_target_properties(henc PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(alianhenc PROPERTIES CLEAN_DIRECT_OUTPUT 1)

set(LINKED_LIB henc ntl gmp pthread boost_program_options)

add_executable(paillier_run ${PROJECT_SOURCE_DIR}/test/test_paillier.cpp)
target_link_libraries(paillier_run ${LINKED_LIB})
add_test(test_paillier ${PROJECT_SOURCE_DIR}/bin/paillier_run)

add_executable(elgamal_run ${PROJECT_SOURCE_DIR}/test/test_elgamal.cpp)
target_link_libraries(elgamal_run ${LINKED_LIB})
add_test(test_elgamal ${PROJECT_SOURCE_DIR}/bin/elgamal_run)

add_executable(she_run ${PROJECT_SOURCE_DIR}/test/test_she.cpp)
target_link_libraries(she_run ${LINKED_LIB})
add_test(test_she ${PROJECT_SOURCE_DIR}/bin/she_run)

add_executable(rsa_run ${PROJECT_SOURCE_DIR}/test/test_rsa.cpp)
target_link_libraries(rsa_run ${LINKED_LIB})
add_test(test_rsa ${PROJECT_SOURCE_DIR}/bin/rsa_run)

# install static and shared library
install(TARGETS henc  alianhenc DESTINATION lib)

# install head files
INSTALL (DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/henc FILES_MATCHING PATTERN "*.h*")
