cmake_minimum_required(VERSION 3.21)
project(ShodanViewer VERSION 0.1.0 LANGUAGES CXX)

configure_file(src/version.h.in version.h @ONLY)
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets Network Sql)

qt_add_executable(ShodanViewer MACOSX_BUNDLE
    src/main.cpp
    src/MainWindow.h src/MainWindow.cpp
    src/ShodanClient.h src/ShodanClient.cpp
    src/HostTableModel.h src/HostTableModel.cpp
    src/CacheStore.h src/CacheStore.cpp
    src/JsonDialog.h src/JsonDialog.cpp
    src/QueryTab.h src/SearchBarWidgets.h
    src/resources.qrc
)

target_link_libraries(ShodanViewer PRIVATE Qt6::Widgets Qt6::Network Qt6::Sql)
target_include_directories(ShodanViewer PRIVATE
    src
    ${CMAKE_CURRENT_BINARY_DIR}
)

if(WIN32)
    set_target_properties(ShodanViewer PROPERTIES WIN32_EXECUTABLE TRUE)
endif()
