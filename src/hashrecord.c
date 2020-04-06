#include "hashrecord.h"

const uint64_t FNV_offset_basis = 0xCBF29CE484222325ULL;
const uint64_t FNV_prime = 0x00000100000001B3ULL;

uint64_t hash64_fnv_1a(uint8_t *data, size_t len)
{
	uint64_t hash = FNV_offset_basis;
	uint8_t byte_of_data; // why this intermediate variable

	for (size_t i = 0; i < len; ++i)
	{
		byte_of_data = data[i];
		hash = hash ^ byte_of_data;
		hash = hash * FNV_prime;
	}

	return hash;
}

uint64_t hash64(uint8_t *data, size_t len)
{
	hash64_fnv_1a(data, len);
}

void InitializeHashRecord(HashRecord *rec, size_t size, size_t keyLen, size_t itemLen)
{
	rec->size = size;
	rec->keyLen = keyLen;
	rec->itemLen = itemLen;

	size_t bufferLen = size * itemLen;
	
	rec->dataMem = malloc(bufferLen);

	rec->isUsed = malloc(size);
	memset(rec->isUsed, 0, size);

	rec->keyMem = malloc(keyLen * size);
	memset(rec->keyMem, 0, keyLen * size);
}

uint64_t HashRecordQueryIndex(const HashRecord *rec, const HashKey *key)
{
	uint64_t index = hash64(key->data, key->len) % rec->size;
	uint64_t keyOffset = index * rec->keyLen;

	while (true)
	{
		bool used = rec->isUsed[ index ];
		bool equal = !memcmp(&rec->keyMem[keyOffset], key->data, rec->keyLen);

		if (!used || (used && equal))
			break;
		else
		{
			index = (index + 1) % rec->size;
			keyOffset += rec->keyLen;
		}
	}

	return index;
}

bool HashRecordQueryExists(const HashRecord *rec, const HashKey *key)
{
	uint64_t index = HashRecordQueryIndex(rec, key);
	return rec->isUsed[ index ];
}

bool HashRecordQueryExistsByIndex(const HashRecord *rec, uint64_t index)
{
	return rec->isUsed[ index ];
}

void *HashRecordQuery(const HashRecord *rec, const HashKey *key)
{
	uint64_t index = HashRecordQueryIndex(rec, key);
	uint64_t keyOffset = index * rec->keyLen;
	uint64_t offset = index * rec->itemLen;
	uint8_t *bytes = &rec->dataMem[ offset ];
	//printf("GET: index: %lu; value: %u \n", index, *(unsigned int *) bytes);
	return bytes;
}

void *HashRecordQueryByIndex(const HashRecord *rec, uint64_t index)
{
	uint64_t offset = index * rec->itemLen;
	uint8_t *bytes = &rec->dataMem[ offset ];
	return bytes;
}

bool HashRecordInsert(HashRecord *rec, const HashKey *key, const void *item)
{
	uint64_t index = HashRecordQueryIndex(rec, key);
	uint64_t keyOffset = index * rec->keyLen;

	// Set used flag on the item
	if (!rec->isUsed[ index ])
	{
		memcpy(&rec->keyMem[keyOffset], key->data, rec->keyLen);
		rec->isUsed[ index ] = true;
	}

	uint64_t offset = index * rec->itemLen;
	uint8_t *bytes = &rec->dataMem[ offset ];
	memcpy(bytes, item, rec->itemLen);
	
	// printf("SET: index: %lu; value: %u \n", index, *(unsigned int *) data);

	return true;
}

bool HashRecordInsertByIndex(HashRecord *rec, uint64_t index, const void *item)
{
	uint64_t keyOffset = index * rec->keyLen;

	// Set used flag on the item
	if (!rec->isUsed[ index ])
	{
		//memcpy(&rec->keyMem[keyOffset], key->data, rec->keyLen);
		rec->isUsed[ index ] = true;
	}

	uint64_t offset = index * rec->itemLen;
	uint8_t *bytes = &rec->dataMem[ offset ];
	memcpy(bytes, item, rec->itemLen);
	
	// printf("SET: index: %lu; value: %u \n", index, *(unsigned int *) data);

	return true;
}

void DestroyHashRecord(HashRecord *rec)
{
	free(rec->keyMem);
	free(rec->dataMem);
	free(rec->isUsed);
}

bool HashRecordRemoveByIndex(HashRecord *rec, uint64_t index)
{
	if (rec->isUsed[index])
	{
		rec->isUsed[index] = false;
		//uint64_t keyOffset = index * rec->keyLen;
		//memset((void *)&rec->keyMem[keyOffset], 0, rec->keyLen);
		
		return true;
	}
	else
	{
		// Wut???

		return false;
	}
}