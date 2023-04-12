#include <Windows.h>

extern "C" DWORDLONG * _fastcall Encr_lilith(DWORDLONG * data, DWORDLONG key[2], DWORDLONG len_of_data);

extern "C" void* Encr_lilith_cwr(DWORDLONG * data, DWORDLONG key[2], DWORDLONG len_of_data)
{
	// copy data before modifing, then return block of memory... somehow 
	LPVOID lpbuf = malloc(len_of_data);
	memcpy_s(lpbuf, len_of_data, data, len_of_data);
	Encr_lilith((DWORDLONG*)lpbuf, key, len_of_data / 8);

	return lpbuf;
}