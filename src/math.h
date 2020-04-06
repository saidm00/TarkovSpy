#ifndef MATH_H
#define MATH_H

//#include <glm/glm.h>
#include "common.h"

typedef struct Vector2
{
    float x;
    float y;
} Vector2;

typedef struct Vector3
{
    float x;
    float y;
    float z;
} Vector3;

typedef struct Quaternion
{
    float x;
    float y;
    float z;
    float w;
} Quaternion;

inline uint32_t Popcount(uint32_t x)
{
    uint32_t num = x - (x >> 1 & 1431655765U);
    uint32_t num2 = (num >> 2 & 858993459U) + (num & 858993459U);
    uint32_t num3 = (num2 >> 4) + num2 & 252645135U;
    uint32_t num4 = num3 + (num3 >> 8);
    return num4 + (num4 >> 16) & 63U;
}

inline uint32_t Log2(uint32_t value)
{
    uint32_t num = value | value >> 1;
    uint32_t num2 = num | num >> 2;
    uint32_t num3 = num2 | num2 >> 4;
    uint32_t num4 = num3 | num3 >> 8;
    return Popcount((num4 | num4 >> 16) >> 1);
}

inline uint32_t BitsRequired(uint32_t min, uint32_t max)
{
    if (min != max)
    {
        return (uint32_t)(Log2((uint32_t)(max - min)) + 1);
    }
    return 0;
}

#endif //MATH_H