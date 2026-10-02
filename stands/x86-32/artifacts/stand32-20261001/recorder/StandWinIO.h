#pragma once
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "fex/Source/Windows/include/winnt.h"
#include "fex/Source/Windows/include/winternl.h"
extern "C" NTSTATUS WINAPI NtReadVirtualMemory(HANDLE,const void*,void*,SIZE_T,SIZE_T*);
#endif
