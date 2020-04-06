#ifndef HASHRECORD_H
#define HASHRECORD_H

#include "common.h"

typedef struct HashRecord
{
    bool    *isUsed;
    uint8_t *keyMem, *dataMem;

    size_t size, keyLen, itemLen;
} HashRecord;

typedef struct HashKey
{
    size_t len;
    void *data;
} HashKey;

void InitializeHashRecord(HashRecord *rec, size_t size, size_t keyLen, size_t itemLen);

uint64_t HashRecordQueryIndex(const HashRecord *rec, const HashKey *key);

bool HashRecordQueryExists(const HashRecord *rec, const HashKey *key);

bool HashRecordQueryExistsByIndex(const HashRecord *rec, uint64_t index);

void *HashRecordQuery(const HashRecord *rec, const HashKey *key);

void *HashRecordQueryByIndex(const HashRecord *rec, uint64_t index);

bool HashRecordInsert(HashRecord *rec, const HashKey *key, const void *item);

bool HashRecordInsertByIndex(HashRecord *rec, uint64_t index, const void *item);

void DestroyHashRecord(HashRecord *rec);

bool HashRecordRemoveByIndex(HashRecord *rec, uint64_t index);


#endif // HASHRECORD_H