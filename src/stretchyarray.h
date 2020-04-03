#ifndef STRETCHYARRAY_H
#define STRETCHYARRAY_H

#include <string.h>
#include <stdlib.h>

typedef struct StretchyArray
{
	uint8_t *data;
	size_t itemLen;
	size_t size; // Element count
	size_t dataLen;
} StretchyArray;


inline void InitializeStretchyArray(StretchyArray *self, size_t itemLen)
{
	self->data = NULL;
	self->itemLen = itemLen;
	self->dataLen = 0;
	self->size = 0;
}

inline void DestroyStretchyArray(StretchyArray *self)
{
	free(self->data);
	self->itemLen = 0;
	self->dataLen = 0;
	self->size = 0;
	self->data = NULL;
}

inline void StretchyArrayPush(StretchyArray *self, const void *item)
{
	size_t initialSize = self->size;

	++self->size;
	self->dataLen = self->itemLen * self->size;
	
	if (initialSize == 0)
	{
		self->data = malloc(self->dataLen);
	}
	else
	{
		self->data = realloc(self->data, self->dataLen);
	}

	memcpy(&self->data[ (self->size-1) * self->itemLen ], item, self->itemLen);
}


inline void StretchyArrayPop(StretchyArray *self)
{
	size_t initialSize = self->size;

	--self->size;
	self->dataLen = self->itemLen * self->size;

	if (initialSize == 1) // went from 1 to 0, free last element
	{
		free(self->data);
	}
	else
	{
		self->data = realloc(self->data, self->dataLen);
	}
}


inline void *StretchyBufferAccess(StretchyArray *self, size_t index)
{
	return (void *) &self->data[ index * self->itemLen ];
}

#endif // STRETCHYARRAY_H