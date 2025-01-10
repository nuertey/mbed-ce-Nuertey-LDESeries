cmake_minimum_required(VERSION 3.20)
cmake_policy(VERSION 3.20)

project(Nuertey-LDESeries)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

set(MBED_APP_JSON_PATH mbed_app.json5)

include(mbed-os/tools/cmake/app.cmake)

include_directories(mbed-os/connectivity/mbedtls)
include_directories(mbed-os/connectivity/mbedtls/include)
include_directories(mbed-os/connectivity/netsocket/include)
include_directories(mbed-os/connectivity/netsocket/include/netsocket)
include_directories(mbed-os/connectivity/lwipstack/lwip/src/include)
include_directories(mbed-os/connectivity/lwipstack/lwip-sys)
include_directories(mbed-os/connectivity/lwipstack/include/lwipstack)

include_directories(mbed-os/platform/randlib/include/mbed-client-randlib)

include_directories(mbed-mqtt/paho_mqtt_embedded_c/MQTTClient/src)
include_directories(mbed-mqtt/paho_mqtt_embedded_c/MQTTPacket/src)

add_subdirectory(mbed-os)

file(GLOB app_sources *.cpp)

add_executable(${CMAKE_PROJECT_NAME} ${app_sources})

target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE cxx_std_20)

target_link_libraries(${CMAKE_PROJECT_NAME} -std=gnu++20)

target_link_libraries(${CMAKE_PROJECT_NAME} mbed-os) # Can also link to mbed-baremetal here
mbed_set_post_build(${CMAKE_PROJECT_NAME})

mbed_finalize_build()
