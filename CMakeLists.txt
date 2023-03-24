cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(pe-builder)

SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

# add_executable(${PROJECT_NAME}
# "src/main.cpp"
# "src/pe.cpp"
# "src/pebuilder.cpp"
# "src/pe.h"
# "src/pebuilder.h"
# )

# add_library(cpp-peglib INTERFACE IMPORTED)
# set_target_properties(cpp-peglib PROPERTIES
#     INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/external/peglib")

add_executable(${PROJECT_NAME}
"src/main.real.cpp"
# "src/mainv2.cpp"
# "src/main.v3.cpp"
# "src/parser.cpp"
)



# target_link_libraries(${PROJECT_NAME} 
#     cpp-peglib)