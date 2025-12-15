#pragma once

#define WINVER			0x0501
#define _WIN32_IE		0x0501
#define _WIN32_WINNT	0x0501

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <intrin.h>
#include <VersionHelpers.h>
#define IS_UPPER(c) \
	(((SIZE_T)(c) - 'A') <= 'Z'-'A')

#define TO_LOWER(c) \
	(IS_UPPER(c) ? (c) + ('a'-'A') : (c))

inline BOOL IsProcessorSupportedSSE2(void)
{
	int cpuInfo[4] = { 0 };

	__try {
		__cpuid(cpuInfo, 0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	if (cpuInfo[0] == 0) {
		return FALSE;
	}

	__cpuid(cpuInfo, 1);

	const DWORD CPU_SUPPORT_CMOV = (1 << 15);
	const DWORD CPU_SUPPORT_MMX = (1 << 23);
	const DWORD CPU_SUPPORT_SSE = (1 << 25);
	const DWORD CPU_SUPPORT_SSE2 = (1 << 26);
	const DWORD CPU_CHECK_BITS = (CPU_SUPPORT_CMOV | CPU_SUPPORT_MMX | CPU_SUPPORT_SSE | CPU_SUPPORT_SSE2);

	return ((cpuInfo[3] & CPU_CHECK_BITS) == CPU_CHECK_BITS);
}

inline BOOL IsAboveWinXP(void)
{
	return IsWindowsVistaOrGreater();
}

inline LPVOID MemAlloc(DWORD uSize)
{
	return HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS,
		uSize);
}

inline void MemFree(LPVOID lpBuf)
{
	if (lpBuf) {
		HeapFree(
			GetProcessHeap(),
			0,
			lpBuf);
	}
}

typedef struct _FILEMAP
{
	HANDLE hFile;
	HANDLE hMap;
	BYTE* lpFileBuf;
	DWORD uSize;
} FILEMAP;

BOOL NR2_OpenFileMap(FILEMAP*, LPCSTR, DWORD);
void NR2_CloseFileMap(FILEMAP*);

void __cdecl NR2_ErrorMsg(const char*, ...);
void __cdecl NR2_Printf(const char*, ...);
BOOL NR2_ExtensionFilter(LPCWSTR, LPCSTR);
BOOL NR2_CreateDirectory(LPCSTR);
BOOL NR2_PutFile(LPCSTR, void*, DWORD);
BOOL NR2_UnpackFile(LPCSTR, void*, DWORD);
void __fastcall NR2_Uncompress(void*, BYTE*);