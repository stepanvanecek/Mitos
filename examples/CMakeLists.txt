include_directories(${MPI_INCLUDE_PATH})
include_directories(${DYNINST_INCLUDE_DIR})
include_directories("..")

set(CMAKE_BUILD_TYPE Debug)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

add_executable(api_test api_test.cpp)
add_executable(matmul matmul.cpp)
add_executable(mpi_matmul mpi_matmul.cpp)
#add_executable(dyninst-test dyninst-test.cpp)

target_link_libraries(api_test mitos symtabAPI)
#target_link_libraries(dyninst-test mitos symtabAPI dl)
target_link_libraries(mpi_matmul ${MPI_LIBRARIES})
