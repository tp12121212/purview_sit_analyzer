cmake_minimum_required(VERSION 3.15)
project(boost_regex_runner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS regex)
find_package(nlohmann_json REQUIRED)

add_executable(boost_regex_runner
    boost_regex_runner.cpp
)

target_include_directories(boost_regex_runner PRIVATE
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(boost_regex_runner
    Boost::regex
    nlohmann_json::nlohmann_json
)

# Make the binary land in a predictable place
set_target_properties(boost_regex_runner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
