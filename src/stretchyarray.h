#ifndef STRETCHYARRAY_H
#define STRETCHYARRAY_H

#include "common.h"

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

inline void *StretchyArrayResize(StretchyArray *self, size_t newSize)
{
	if (self->size > 0)
	{
		self->data = realloc(self->data, newSize * self->itemLen);
	}
	else
	{
		self->data = malloc(newSize * self->itemLen);
	}

	self->size = newSize;
}

inline void StretchyBufferPopAt(StretchyArray *self, size_t index)
{
	if (self->size - 1 == 0)
	{
		free(self->data);
		self->size = 0;
	}
	else
	{
		for (size_t i = index; i < self->size - 1; ++i)
		{
			memcpy((void *)&self->data[(i) * self->itemLen], (const void *)&self->data[(i+1) * self->itemLen], self->itemLen);
		}

		self->data = realloc(self->data, self->size - 1);
		--self->size;		
	}
}



// cock sucker. grandmas rusty asscrack. her dry queef is the smell of your breath
#endif // STRETCHYARRAY_H