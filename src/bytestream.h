#ifndef BYTESTREAM_H
#define BYTESTREAM_H

#include "math.h"
#include "common.h"

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

static inline void CalculateDataForQuantizing(float min, float max, float step, float* delta, uint32_t* maxIntegerValue, uint32_t* bits)
{
	*delta = max - min;
	float f = *delta / step;
	*maxIntegerValue = (uint32_t)ceil(f);
	*bits = BitsRequired(0, *maxIntegerValue);
}

static inline void InitializeFloatQuantizer(FloatQuantizer *quantizer, float min, float max, float step, bool checkBounds)
{
	quantizer->min = min;
	quantizer->max = max;
	quantizer->step = step;
	quantizer->checkBounds = checkBounds;
	CalculateDataForQuantizing(min, max, step, &quantizer->delta, &quantizer->maxIntegerValue, &quantizer->bitsRequired);
}

static inline float DequantizeUInt32ToFloat(uint32_t integerValue, float min, int maxIntegerValue, float delta)
{
	return integerValue / (float)maxIntegerValue * delta + min;
}

static inline float FloatQuantizerDequantizeUint32(FloatQuantizer const *quantizer, uint32_t integerValue)
{
	return integerValue / (float)quantizer->maxIntegerValue * quantizer->delta + quantizer->min;
}
typedef struct ByteStream
{
	uint8_t *data;
	size_t size;
	size_t head;
	//bool initializedByRef;
}
ByteStream;

static inline ByteStream CreateByteStream(const uint8_t *data, size_t size)
{
	ByteStream newStream;
	newStream.data = (uint8_t *)malloc(size);
	memcpy(newStream.data, data, size);
	newStream.head = 0;
	newStream.size = size;
	//ndewStream.initializedByRef = false;
	return newStream;
}

static inline ByteStream CreateByteStreamByRef(uint8_t *data, size_t size)
{
	ByteStream newStream;
	newStream.data = data;//malloc(size);
	//memcpy(newStream.data, data, size);
	newStream.head = 0;
	newStream.size = size;
	//newStream.initializedByRef = true;//false;
	return newStream;
}

static inline void InitializeByteStreamByRef(ByteStream *stream, uint8_t *data, size_t size)
{
	stream->data = data;
	stream->size = size;
	stream->head = 0;
	//stream->initializedByRef = true;
}

static inline void InitializeByteStream(ByteStream *stream, const uint8_t *data, size_t size)
{
	stream->data = malloc(size);
	memcpy(stream->data, data, size);
	stream->size = size;
	stream->head = 0;
	//stream->initializedByRef = false;
}

static inline void DestroyByteStream(ByteStream *stream)
{
	//if (!stream->initializedByRef)
	//{
		free(stream->data);
		stream->data = NULL;
		stream->size = 0;
		stream->head = 0;
	//}
	//else
	//{
	//	// What you doin!?
	//}
}

static inline uint8_t ByteStreamReadUInt8(ByteStream *stream)
{
	return *(uint8_t *) &stream->data[ stream->head++ ];
}

static inline uint16_t ByteStreamReadUInt16(ByteStream *stream)
{
	uint16_t value = *(uint16_t *) &stream->data[stream->head];
	stream->head += sizeof(uint16_t);
	return value;
}

static inline uint32_t ByteStreamReadUInt32(ByteStream *stream)
{
	uint32_t value = *(uint32_t *) &stream->data[stream->head];
	stream->head += sizeof(uint32_t);
	return value;
}

static inline uint64_t ByteStreamReadUInt64(ByteStream *stream)
{
	uint64_t value = *(uint64_t *) &stream->data[stream->head];
	stream->head += sizeof(uint64_t);
	return value;
}

static inline int8_t ByteStreamReadInt8(ByteStream *stream)
{
	return *(int8_t *) &stream->data[ stream->head++ ];
}

static inline int16_t ByteStreamReadInt16(ByteStream *stream)
{
	int16_t value = *(int16_t *) &stream->data[stream->head];
	stream->head += sizeof(int16_t);
	return value;
}

static inline int32_t ByteStreamReadInt32(ByteStream *stream)
{
	int32_t value = *(int32_t *) &stream->data[stream->head];
	stream->head += sizeof(int32_t);
	return value;
}

static inline int64_t ByteStreamReadInt64(ByteStream *stream)
{
	int64_t value = *(int64_t *) &stream->data[stream->head];
	stream->head += sizeof(int64_t);
	return value;
}

static inline bool ByteStreamReadBool(ByteStream *stream)
{
	return *(bool *) &stream->data[ stream->head++ ];
}

static inline uint8_t ByteStreamReadByte(ByteStream *stream)
{
	return ByteStreamReadUInt8(stream);
}

static inline float ByteStreamReadFloat(ByteStream *stream)
{
	float value = *(float *) &stream->data[stream->head];
	stream->head += sizeof(float);
	return value;
}

static inline Vector3 ByteStreamReadVector3(ByteStream *stream)
{
	Vector3 value;
	value.x = ByteStreamReadFloat(stream);
	value.y = ByteStreamReadFloat(stream);
	value.z = ByteStreamReadFloat(stream);
	return value;
}

static inline Quaternion ByteStreamReadQuaternion(ByteStream *stream)
{
	Quaternion value;
	value.x = ByteStreamReadFloat(stream);
	value.y = ByteStreamReadFloat(stream);
	value.z = ByteStreamReadFloat(stream);
	value.w = ByteStreamReadFloat(stream);
	return value;
}

static inline uint8_t *ByteStreamReadBytes16(ByteStream *stream, uint16_t *outSize)
{
	uint16_t size = ByteStreamReadUInt16(stream);
	
	if (outSize != NULL) *outSize = size;
	
	if (!size)
	{
		// If outSize valid pointer, write size to it
		return NULL;
	}
	
	stream->head += size;
	return &stream->data[stream->head];
}

static inline void ByteStreamSeek(ByteStream *stream, size_t head)
{
	stream->head = head;
}

static inline void ByteStreamSeekRel(ByteStream *stream, int64_t offset)
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

static inline NetPacketBaseHeader ByteStreamDecodeNetPacketBaseHeader(ByteStream *stream)
{
	NetPacketBaseHeader header = *(NetPacketBaseHeader *) &stream->data[ stream->head ];
	stream->head += sizeof(NetPacketBaseHeader);
	header.connectionID = ntohs(header.connectionID);
	return header;
}

static inline NetPacketHeader ByteStreamDecodeNetPacketHeader(ByteStream *stream)
{
	NetPacketHeader header = *(NetPacketHeader *) &stream->data[ stream->head ];
	stream->head += sizeof(NetPacketHeader);
	header.connectionID = ntohs(header.connectionID);
	header.packetID = ntohs(header.packetID);
	header.sessionID = ntohs(header.sessionID);
	return header;
}

static inline NetMessageHeader ByteStreamDecodeNetMessageHeader(ByteStream *stream)
{
	NetMessageHeader header = *(NetMessageHeader *) &stream->data[ stream->head ];
	stream->head += sizeof(NetMessageHeader);
	header.len = ntohs(header.len);
	return header;
}

static inline NetMessageReliableHeader ByteStreamDecodeNetMessageReliableHeader(ByteStream *stream)
{
	NetMessageReliableHeader header = *(NetMessageReliableHeader *) &stream->data[ stream->head ];
	stream->head += sizeof(NetMessageReliableHeader);
	header.messageID = ntohs(header.messageID);
	return header;
}

static inline PacketAcks128 ByteStreamDecodePacketAcks128(ByteStream *stream)
{
	PacketAcks128 acks = *(PacketAcks128 *) &stream->data[ stream->head ];
	stream->head += sizeof(PacketAcks128);

	acks.messageID = ntohs(acks.messageID);

	for (size_t i = 0; i < 4; ++i)
		acks.data[i] = ntohl(acks.data[i]);

	return acks;
}

static inline NetMessageFragmentedHeader ByteStreamDecodeNetMessageFragmentedHeader(ByteStream *stream)
{
	NetMessageFragmentedHeader header = *(NetMessageFragmentedHeader *) &stream->data[ stream->head ];
	stream->head += sizeof(NetMessageFragmentedHeader);
	
	return header;
}

static inline size_t ByteStreamRemaining(const ByteStream *stream)
{
	return stream->head >= stream->size ? 0 : (stream->size - stream->head);
}

static inline uint8_t *ByteStreamHeadAddr(const ByteStream *stream)
{
	return &stream->data[ stream->head ];
}

static inline const uint8_t *ByteStreamHeadAddrConst(const ByteStream *stream)
{
	return (const uint8_t *) &stream->data[ stream->head ];
}

#endif // BYTESTREAM_H