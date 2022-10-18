#pragma once

#include <cstdint>
#include <cstdio>

class Random
{
public:
    Random();
    ~Random();

    void get(void *data, std::size_t size);

private:
    FILE *file;
};
