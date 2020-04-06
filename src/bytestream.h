#ifndef BYTESTREAM_H
#define BYTESTREAM_H

#include "math.h"

#include <Windowsx.h>
#include <WinSock2.h>

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

inline void CalculateDataForQuantizing(float min, float max, float step, float* delta, uint32_t* maxIntegerValue, uint32_t* bits)
{
    *delta = max - min;
    float f = *delta / step;
    *maxIntegerValue = (uint32_t)ceil(f);
    *bits = BitsRequired(0, *maxIntegerValue);
}

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

typedef struct ByteStream
{
    uint8_t *data;
    size_t size;
    size_t head;
    bool initializedByRef;
}
ByteStream;

inline ByteStream CreateByteStream(const uint8_t *data, size_t size)
{
    ByteStream newStream;
    newStream.data = malloc(size);
    memcpy(newStream.data, data, size);
    newStream.head = 0;
    newStream.size = size;
    newStream.initializedByRef = false;
    return newStream;
}

inline ByteStream CreateByteStreamByRef(uint8_t *data, size_t size)
{
    ByteStream newStream;
    newStream.data = data;//malloc(size);
    //memcpy(newStream.data, data, size);
    newStream.head = 0;
    newStream.size = size;
    newStream.initializedByRef = true;//false;
    return newStream;
}

inline void InitializeByteStreamByRef(ByteStream *stream, uint8_t *data, size_t size)
{
    stream->data = data;
    stream->size = size;
    stream->head = 0;
    stream->initializedByRef = true;
}

inline void InitializeByteStream(ByteStream *stream, const uint8_t *data, size_t size)
{
    stream->data = malloc(size);
    memcpy(stream->data, data, size);
    stream->size = size;
    stream->head = 0;
    stream->initializedByRef = false;
}

inline void DestroyByteStream(ByteStream *stream)
{
    if (!stream->initializedByRef)
    {
        free(stream->data);
        stream->data = NULL;
        stream->size = 0;
        stream->head = 0;
    }
    else
    {
        // What you doin!?
    }
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

inline void ByteStreamSeekRel(ByteStream *stream, int64_t offset)
{
    stream->head += offset;
}

// UNET Reading functionality

// VERY IMPORTANT!!!
#pragma pack(push, 1)

typedef struct NetPacketBaseHeader
{
    uint16_t connectionID;
} NetPacketBaseHeader;

typedef struct NetPacketHeader
{
    uint16_t connectionID;
    uint16_t packetID;
    uint16_t sessionID;
} NetPacketHeader;

typedef struct NetMessageHeader
{
    uint8_t channelID;
    uint16_t len;
} NetMessageHeader;

typedef struct NetMessageReliableHeader
{
    uint16_t messageID;
} NetMessageReliableHeader;

typedef struct NetMessageOrderedHeader
{
    uint8_t orderedMessageID;
} NetMessageOrderedHeader;

/* Struct for message ID for f*cked up fragmented messages :( */
typedef struct NetMessageFragmentedHeader
{
    uint8_t fragmentedMessageID;
    uint8_t fragmentIdx;
    uint8_t fragmentAmnt;
} NetMessageFragmentedHeader;

/* Struct for Acks packet info */
typedef struct PacketAcks128
{
    uint16_t messageID;
    uint32_t data[4];
} PacketAcks128;

#pragma pack(pop)

inline NetPacketBaseHeader ByteStreamDecodeNetPacketBaseHeader(ByteStream *stream)
{
    NetPacketBaseHeader header = *(NetPacketBaseHeader *) &stream->data[ stream->head ];
    stream->head += sizeof(NetPacketBaseHeader);
    header.connectionID = ntohs(header.connectionID);
    return header;
}

inline NetPacketHeader ByteStreamDecodeNetPacketHeader(ByteStream *stream)
{
    NetPacketHeader header = *(NetPacketHeader *) &stream->data[ stream->head ];
    stream->head += sizeof(NetPacketHeader);
    header.connectionID = ntohs(header.connectionID);
    header.packetID = ntohs(header.packetID);
    header.sessionID = ntohs(header.sessionID);
    return header;
}

inline NetMessageHeader ByteStreamDecodeNetMessageHeader(ByteStream *stream)
{
    NetMessageHeader header = *(NetMessageHeader *) &stream->data[ stream->head ];
    stream->head += sizeof(NetMessageHeader);
    header.len = ntohs(header.len);
    return header;
}

inline NetMessageReliableHeader ByteStreamDecodeNetMessageReliableHeader(ByteStream *stream)
{
    NetMessageReliableHeader header = *(NetMessageReliableHeader *) &stream->data[ stream->head ];
    stream->head += sizeof(NetMessageReliableHeader);
    header.messageID = ntohs(header.messageID);
    return header;
}

inline PacketAcks128 ByteStreamDecodePacketAcks128(ByteStream *stream)
{
    PacketAcks128 acks = *(PacketAcks128 *) &stream->data[ stream->head ];
    stream->head += sizeof(PacketAcks128);

    acks.messageID = ntohs(acks.messageID);

    for (size_t i = 0; i < 4; ++i)
        acks.data[i] = ntohl(acks.data[i]);

    return acks;
}

inline size_t ByteStreamRemaining(const ByteStream *stream)
{
    return stream->head >= stream->size ? 0 : (stream->size - stream->head);
}

inline uint8_t *ByteStreamHeadAddr(const ByteStream *stream)
{
    return &stream->data[ stream->head ];
}

inline const uint8_t *ByteStreamHeadAddrConst(const ByteStream *stream)
{
    return (const uint8_t *) &stream->data[ stream->head ];
}

#endif // BYTESTREAM_H