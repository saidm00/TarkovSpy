#ifndef BYTESTREAM_H
#define BYTESTREAM_H

#include "math.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct ByteStream
{
    uint8_t *data;
    size_t len;
    size_t head;
}
ByteStream;

inline void CalculateDataForQuantizing(float min, float max, float step, float* delta, uint32_t* maxIntegerValue, uint32_t* bits)
{
    *delta = max - min;
    float f = *delta / step;
    *maxIntegerValue = (uint32_t)ceil(f);
    *bits = BitsRequired(0, *maxIntegerValue);
}

typedef struct FloatQuantizer
{
    float min;
    float max;
    float step;
    uint32_t bitsRequired;
    float delta;
    uint32_t maxIntegerValue;
    bool checkBounds;
}
FloatQuantizer;

inline void InitializeFloatQuantizer(FloatQuantizer *quantizer, float min, float max, float step, bool checkBounds)
{
    quantizer->min = min;
    quantizer->max = max;
    quantizer->step = step;
    quantizer->checkBounds = checkBounds;
    CalculateDataForQuantizing(min, max, step, &quantizer->delta, &quantizer->maxIntegerValue, &quantizer->bitsRequired);
}

inline float DequantizeUInt32ToFloat(uint32_t integerValue, float min, int maxIntegerValue, float delta)
{
    return integerValue / (float)maxIntegerValue * delta + min;
}

inline float FloatQuantizerDequantizeUint32(FloatQuantizer const *quantizer, uint32_t integerValue)
{
    return integerValue / (float)quantizer->maxIntegerValue * quantizer->delta + quantizer->min;
}

typedef struct Vector2Quantizer
{
    FloatQuantizer x;
    FloatQuantizer y;
} Vector2Quantizer;

typedef struct Vector3Quantizer
{
    FloatQuantizer x;
    FloatQuantizer y;
    FloatQuantizer z;
} Vector3Quantizer;

typedef struct QuaternionQuantizer
{
    FloatQuantizer x;
    FloatQuantizer y;
    FloatQuantizer z;
    FloatQuantizer w;
} QuaternionQuantizer;


inline void InitializeByteStream(ByteStream *stream, uint8_t *data, size_t len)
{
    stream->data = malloc(len);
    memcpy(stream->data, data, len);
    stream->len = len;
    stream->head = 0;
}

inline void DestroyByteStream(ByteStream *stream)
{
    free(stream->data);
    stream->data = NULL;
    stream->len = 0;
    stream->head = 0;
}

inline uint8_t ByteStreamReadUInt8(ByteStream *stream)
{
    return *(uint8_t *) &stream->data[ stream->head++ ];
}

inline uint16_t ByteStreamReadUInt16(ByteStream *stream)
{
    uint16_t value = *(uint16_t *) &stream->data[stream->head];
    stream->head += sizeof(uint16_t);
    return value;
}

inline uint32_t ByteStreamReadUInt32(ByteStream *stream)
{
    uint32_t value = *(uint32_t *) &stream->data[stream->head];
    stream->head += sizeof(uint32_t);
    return value;
}

inline uint64_t ByteStreamReadUInt64(ByteStream *stream)
{
    uint64_t value = *(uint64_t *) &stream->data[stream->head];
    stream->head += sizeof(uint64_t);
    return value;
}

inline int8_t ByteStreamReadInt8(ByteStream *stream)
{
    return *(int8_t *) &stream->data[ stream->head++ ];
}

inline int16_t ByteStreamReadInt16(ByteStream *stream)
{
    int16_t value = *(int16_t *) &stream->data[stream->head];
    stream->head += sizeof(int16_t);
    return value;
}

inline int32_t ByteStreamReadInt32(ByteStream *stream)
{
    int32_t value = *(int32_t *) &stream->data[stream->head];
    stream->head += sizeof(int32_t);
    return value;
}

inline int64_t ByteStreamReadInt64(ByteStream *stream)
{
    int64_t value = *(int64_t *) &stream->data[stream->head];
    stream->head += sizeof(int64_t);
    return value;
}

inline bool ByteStreamReadBool(ByteStream *stream)
{
    return *(bool *) &stream->data[ stream->head++ ];
}

inline float ByteStreamReadFloat(ByteStream *stream)
{
    float value = *(float *) &stream->data[stream->head];
    stream->head += sizeof(float);
    return value;
}

inline Vector3 ByteStreamReadVector3(ByteStream *stream)
{
    Vector3 value;
    value.x = ByteStreamReadFloat(stream);
    value.y = ByteStreamReadFloat(stream);
    value.z = ByteStreamReadFloat(stream);
    return value;
}

inline void ByteStreamSeek(ByteStream *stream, size_t head)
{
    stream->head = head;
}

#endif // BYTESTREAM_H