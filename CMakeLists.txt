cmake_minimum_required(VERSION 3.16)

string(ASCII 27 Esc)
set(ColourReset "${Esc}[m")
set(Green       "${Esc}[32m")

# prepare cross-compiling to Windows: cmake -DWINDOWS=1
if(DEFINED WINDOWS)
    set(CMAKE_SYSTEM_NAME Windows)
    set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
    set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-c++)
    message("${Green}Configuring build for cross-compiling to Windows.${ColourReset}")
    set(ignoreMe "${WINDOWS}")
else()
    message("${Green}Defaulting to Linux build.${ColourReset}")
endif()

project(steganography)
include_directories(ext)

add_library(
    stb STATIC
    ext/stb/stb_image.c
    ext/stb/stb_image_write.c
)

add_library(
    zlib STATIC
	ext/zlib/adler32.c
	ext/zlib/compress.c
	ext/zlib/crc32.c
	ext/zlib/crc32.h
	ext/zlib/deflate.c
	ext/zlib/gzclose.c
	ext/zlib/gzlib.c
	ext/zlib/gzread.c
	ext/zlib/gzwrite.c
	ext/zlib/infback.c
	ext/zlib/inffast.c
	ext/zlib/inflate.c
	ext/zlib/inftrees.c
	ext/zlib/trees.c
	ext/zlib/uncompr.c
	ext/zlib/zutil.c)

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_STANDARD_REQUIRED On)

add_library(
    steganography_lib STATIC
        src/aes.cpp
	src/crc32.cpp
	src/image.cpp
	src/sha256.cpp
)

# resolve name conflict for lib and exe in cmake
set_property(TARGET steganography_lib PROPERTY OUTPUT_NAME steganography)

add_executable(
    steganography
    src/main.cpp
)

target_link_libraries(
    steganography
    steganography_lib
    stb
    zlib
)

# prepare cross-compiling to Windows: cmake -DWINDOWS=1
if(DEFINED WINDOWS)
    target_link_options(
        steganography PUBLIC
            -static
    )
    target_link_libraries(
        steganography
            bcrypt
    )
endif()
