#pragma once

#include <Windows.h>

extern "C" __declspec(dllexport) CONST VOID* Encr_lilith_cwr(DWORDLONG * data, DWORDLONG key[2], DWORDLONG len_of_data);