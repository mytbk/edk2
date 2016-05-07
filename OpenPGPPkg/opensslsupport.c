#include <string.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>

int errno;

void *malloc(size_t size)
{
	return AllocatePool((UINTN)size);
}

void free(void *ptr)
{
	FreePool(ptr);
}

void *realloc(void *ptr, size_t size)
{
	void *tmp = AllocatePool((UINTN)size);
	memcpy(tmp, ptr, size);
	FreePool(ptr);
	return tmp;
}
