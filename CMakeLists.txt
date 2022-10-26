cmake_minimum_required(VERSION 3.16)
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

add_executable(
    steganography
    src/aes.cpp
    src/crc32.cpp
    src/image.cpp
    src/main.cpp
    src/sha256.cpp
)

target_link_libraries(
    steganography
    stb
    zlib
)
