cmake_minimum_required(VERSION 3.16)
project(checkin-gateway VERSION 1.2.8 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)

add_executable(checkin-gateway
  src/main.cpp
  src/config.cpp
  src/util.cpp
  src/zk_device.cpp
  src/http_client.cpp
  src/device_identity.cpp
  src/ingest.cpp
  src/store.cpp
  src/gateway.cpp
  src/probe.cpp
)

target_include_directories(checkin-gateway PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(checkin-gateway PRIVATE
  CURL::libcurl
  OpenSSL::SSL
  OpenSSL::Crypto
  SQLite::SQLite3
  nlohmann_json::nlohmann_json
  pthread
)

install(TARGETS checkin-gateway RUNTIME DESTINATION bin)
install(PROGRAMS scripts/checkin-gatewayctl DESTINATION sbin)
install(FILES config/checkin-gateway.conf.example DESTINATION share/checkin-gateway)
install(FILES systemd/checkin-gateway.service DESTINATION lib/systemd/system)

add_executable(checkin-ota
  src/ota_main.cpp
  src/ota.cpp
  src/config.cpp
  src/util.cpp
  src/http_client.cpp
  src/device_identity.cpp
  src/store.cpp
)
target_include_directories(checkin-ota PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(checkin-ota PRIVATE
  CURL::libcurl OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3 nlohmann_json::nlohmann_json pthread)
install(TARGETS checkin-ota RUNTIME DESTINATION bin)
install(FILES systemd/checkin-ota.service DESTINATION lib/systemd/system)
