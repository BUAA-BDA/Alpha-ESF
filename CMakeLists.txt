cmake_minimum_required(VERSION 3.0)
project(mpsi-ca VERSION 1.0)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")



set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR})


set(CMAKE_CXX_STANDARD 11)
# set(CMAKE_CXX_FLAGS "-fsanitize=address -g")
add_compile_options(-std=c++11
                    -Wall
                    -Wextra
                    -pedantic
                    -O2)

# find_package(Boost 1.71.0 COMPONENTS serialization)

if(NOT TARGET boost::serialization)
  find_package(Boost 1.77.0 COMPONENTS serialization)
  add_library(boost::serialization INTERFACE IMPORTED)
  set_target_properties(boost::serialization PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${Boost_INCLUDE_DIRS}"
    INTERFACE_LINK_LIBRARIES "${Boost_SERIALIZATION_LIBRARIES}")
endif()

include_directories(include ${Boost_INCLUDE_DIRS})


aux_source_directory(src DIR_SRCS)

add_executable(main ${DIR_SRCS} "UserService.cpp" "UserClient.cpp" "Main.cpp")

# add_executable(HE_psi_client ${DIR_SRCS} "UserClient.cpp")

find_package(cryptoTools REQUIRED)

# target_link_libraries(HE_psi_service oc::cryptoTools henc ntl gmp pthread boost::serialization)

target_link_libraries(main oc::cryptoTools henc ntl gmp pthread boost::serialization boost_program_options)
