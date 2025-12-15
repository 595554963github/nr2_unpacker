#include "nr2_unpacker.h"
#include <strsafe.h>
#include <stdarg.h>
#include <tchar.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#define NR2_APPVERSION		"v1.0"
#define NR2_APPTITLE		"《超次元游戏海王星Re;Birth2》解包工具 " NR2_APPVERSION
#define NR2_MAXTEXT			1024

#define NR2_DWTABLELEN		256
#define NR2_DWHINTBITS		10

typedef struct _DW_PACHEADER
{
	BYTE magic[8];// "DW_PACK\0"
	DWORD file_pos;
	DWORD file_cnt;
	DWORD status;
} DW_PACHEADER;

typedef struct _DW_PACFILE
{
	DWORD a;
	WORD file_index;
	WORD b;
	BYTE path[264];
	DWORD pack_size;
	DWORD unpack_size;
	DWORD packed_flag;
	DWORD file_offset;
} DW_PACFILE;

typedef struct _DW_PACINFO
{
	DWORD unpack_size;
	DWORD pack_size;
	DWORD data_offset;
} DW_PACINFO;

typedef struct _DW_PACDATA
{
	DWORD magic;// 0x1234
	DWORD pack_cnt;
	DWORD file_type;
	DWORD hdr_offset;
	DW_PACINFO info[1];	
} DW_PACDATA;


static HANDLE __appstd = NULL;

BOOL NR2_UnpackFile(LPCSTR path, void* data, DWORD pack_size);
void __fastcall NR2_Uncompress(void* data, BYTE* buf);

#ifdef _DEBUG
int APIENTRY WinMain(
	HINSTANCE hInst,
	HINSTANCE hPrevInst,
	LPSTR pCmdLine,
	int nCmdShow)
#else
int main()
#endif
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DW_PACHEADER hdr;
	DW_PACFILE* pf = NULL;
	DW_PACDATA* src_buf = NULL;
	DWORD pf_len = 0;
	DWORD src_len = 0;
	WCHAR** argv = NULL;
	int argc;
	WCHAR* filterW = NULL;
	DWORD size, offset;
	DWORD i, j, ret;
	char* fpath, * ext;
	char path[NR2_MAXTEXT];
	char temp[NR2_MAXTEXT];
	char* lastSlash;

	if (!IsProcessorSupportedSSE2()) {
		MessageBoxA(NULL, "处理器不支持SSE2指令集", "错误", MB_ICONERROR);
		ExitProcess(ERROR_INSTALL_PLATFORM_UNSUPPORTED);
	}

	if (!IsAboveWinXP()) {
		MessageBoxA(NULL, "Windows版本过旧，需要XP以上版本", "错误", MB_ICONERROR);
		ExitProcess(ERROR_OLD_WIN_VERSION);
	}

	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc <= 1) {
	ErrShowHelp:
		MessageBoxA(NULL,
			"用法:\nnr2_unpacker <输入.pac>\n\n示例:\nnr2_unpacker c:\\SYSTEM00000.pac",
			"用法说明", MB_ICONINFORMATION);
		goto ErrExit;
	}

	AllocConsole();
	__appstd = GetStdHandle(STD_OUTPUT_HANDLE);

	printf(NR2_APPTITLE "\n");

	for (i = 1; i < (unsigned int)argc; ++i) {
		if (WideCharToMultiByte(CP_ACP, 0, argv[i], -1, path, NR2_MAXTEXT, NULL, NULL) == 0) {
			MessageBoxA(NULL, "错误:路径转换失败", "错误", MB_ICONERROR);
			goto ErrExit;
		}

		printf("输入文件: %s\n", path);

		ext = strrchr(path, '.');
		if (!ext || _stricmp(ext, ".pac") != 0) {
			goto ErrShowHelp;
		}

		hFile = CreateFileA(
			path,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hFile == INVALID_HANDLE_VALUE) {
			char errorMsg[256];
			sprintf_s(errorMsg, "错误:无法打开文件，错误代码:%lu", GetLastError());
			MessageBoxA(NULL, errorMsg, "错误", MB_ICONERROR);
			goto ErrExit;
		}

		if (!ReadFile(hFile, &hdr, sizeof(DW_PACHEADER), &ret, NULL) || ret != sizeof(DW_PACHEADER)) {
			MessageBoxA(NULL, "错误:读取文件头失败", "错误", MB_ICONERROR);
			goto ErrExit;
		}

		if (memcmp(hdr.magic, "DW_PACK", 7) != 0) {
			MessageBoxA(NULL, "错误:不支持的文件格式", "错误", MB_ICONERROR);
			goto ErrExit;
		}

		size = sizeof(DW_PACFILE) * hdr.file_cnt;
		offset = size + sizeof(DW_PACHEADER);

		if (size == 0) {
			MessageBoxA(NULL, "错误:PAC文件中没有文件", "错误", MB_ICONERROR);
			goto ErrExit;
		}

		if (pf_len < size) {
			MemFree(pf);
			pf = (DW_PACFILE*)MemAlloc(size);
			if (!pf) {
				MessageBoxA(NULL, "错误:内存分配失败", "错误", MB_ICONERROR);
				goto ErrExit;
			}
			pf_len = size;
		}

		if (!ReadFile(hFile, pf, size, &ret, NULL) || ret != size) {
			MessageBoxA(NULL, "错误:读取文件条目失败", "错误", MB_ICONERROR);
			goto ErrExit;
		}

		if (ext) *ext = '\0';

		size_t pathLen = strlen(path);
		if (pathLen > 0 && path[pathLen - 1] != '\\') {
			if (pathLen + 1 < NR2_MAXTEXT) {
				path[pathLen] = '\\';
				path[pathLen + 1] = '\0';
			}
		}
		fpath = path + strlen(path);

		filterW = ((i + 1) < (unsigned int)argc && argv[i + 1][0] == L'*') ? argv[++i] : NULL;
		for (j = 0; j < hdr.file_cnt; ++j) {
			if (!pf[j].pack_size || !pf[j].unpack_size) {
				continue;
			}

			if (filterW) {
				char fileExt[32];
				char* fileDot = strrchr((char*)pf[j].path, '.');
				if (fileDot) {
					strcpy_s(fileExt, sizeof(fileExt), fileDot);
					_strlwr_s(fileExt, sizeof(fileExt));

					char filterExt[256];
					WideCharToMultiByte(CP_ACP, 0, filterW, -1, filterExt, sizeof(filterExt), NULL, NULL);
					_strlwr_s(filterExt, sizeof(filterExt));

					if (strstr(filterExt, fileExt) == NULL) {
						continue;
					}
				}
			}

			printf("%u/%u: %s\n", j + 1, hdr.file_cnt, pf[j].path);

			if (SetFilePointer(hFile, offset + pf[j].file_offset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
				MessageBoxA(NULL, "错误:文件定位失败", "错误", MB_ICONERROR);
				goto ErrExit;
			}

			if (src_len < pf[j].pack_size + 2) {
				MemFree(src_buf);
				src_buf = (DW_PACDATA*)MemAlloc(pf[j].pack_size + 2);
				if (!src_buf) {
					MessageBoxA(NULL, "错误:内存分配失败", "错误", MB_ICONERROR);
					goto ErrExit;
				}
				src_len = pf[j].pack_size;
			}

			if (!ReadFile(hFile, src_buf, pf[j].pack_size, &ret, NULL) || ret != pf[j].pack_size) {
				MessageBoxA(NULL, "错误:读取压缩数据失败", "错误", MB_ICONERROR);
				goto ErrExit;
			}

			strcpy_s(fpath, NR2_MAXTEXT - (fpath - path), (char*)pf[j].path);
			strcpy_s(temp, sizeof(temp), path);

			lastSlash = strrchr(temp, '\\');
			if (lastSlash) {
				*lastSlash = '\0';
			}

			char* dirPtr = temp;
			while (*dirPtr) {
				if (*dirPtr == '\\') {
					char saveChar = *(dirPtr + 1);
					*(dirPtr + 1) = '\0';
					CreateDirectoryA(temp, NULL);
					*(dirPtr + 1) = saveChar;
				}
				dirPtr++;
			}
			CreateDirectoryA(temp, NULL);

			if (pf[j].packed_flag == 1) {
				if (!NR2_UnpackFile(path, src_buf, pf[j].pack_size)) {
					goto ErrExit;
				}
			}
			else {
				if (!NR2_PutFile(path, src_buf, pf[j].pack_size)) {
					goto ErrExit;
				}
			}
		}

		printf("完成\n");
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

ErrExit:
	if (__appstd) {
		FreeConsole();
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}
	if (argv) {
		LocalFree(argv);
	}
	MemFree(pf);
	MemFree(src_buf);

#ifdef _DEBUG
	return 0;
#else
	ExitProcess(0);
#endif
}

void __cdecl NR2_ErrorMsg(const char* fmt, ...)
{
	char str[NR2_MAXTEXT];
	va_list arg;

	va_start(arg, fmt);
	vsprintf_s(str, NR2_MAXTEXT, fmt, arg);
	va_end(arg);
	MessageBoxA(GetConsoleWindow(), str, NR2_APPTITLE, MB_ICONWARNING);
}

void __cdecl NR2_Printf(const char* fmt, ...)
{
	char str[NR2_MAXTEXT];
	va_list arg;
	DWORD len;

	va_start(arg, fmt);
	vsprintf_s(str, NR2_MAXTEXT, fmt, arg);
	va_end(arg);

	len = (DWORD)strlen(str);
	str[len] = '\n';
	if (__appstd) {
		WriteFile(__appstd, str, len + 1, &len, NULL);
	}
}

BOOL NR2_ExtensionFilter(LPCWSTR filterW, LPCSTR path)
{
	const WCHAR* p = filterW;
	const char* s, * ext;

	ext = strrchr(path, '.');
	if (!ext) {
		return FALSE;
	}

	while (*p == L'*') {
		if (*(p + 1) == L'.' && *(p + 2) == L'*') {
			return TRUE; // *.*
		}

		s = ext;
		p = p + 1;

		while (1) {
			DWORD c1 = *p++;
			DWORD c2 = *s++;

			if (!c1) {
				return !c2;
			}

			if (c1 == L';') {
				if (!c2) {
					return TRUE;
				}
				break;
			}
			else if (TO_LOWER(c1) != TO_LOWER(c2)) {
				while ((c1 = *p++) != L';') {
					if (!c1) {
						return FALSE;
					}
				}
				break;
			}
		}
	}
	return FALSE;
}

BOOL NR2_CreateDirectory(LPCSTR lpszPath)
{
	DWORD attr;
	WCHAR path[NR2_MAXTEXT];

	attr = GetFileAttributesA(lpszPath);
	if (attr != INVALID_FILE_ATTRIBUTES) {
		return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
	}

	if (MultiByteToWideChar(CP_ACP, 0, lpszPath, -1, path, NR2_MAXTEXT) == 0) {
		return FALSE;
	}
	return (SHCreateDirectory(NULL, path) == ERROR_SUCCESS);
}

BOOL NR2_OpenFileMap(FILEMAP* map, LPCSTR path, DWORD size)
{
	map->hFile = CreateFileA(
		path,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	map->hMap = NULL;
	map->lpFileBuf = NULL;
	map->uSize = size;

	if (map->hFile == INVALID_HANDLE_VALUE) {
		map->hFile = NULL;
		return FALSE;
	}
	else {
		map->hMap = CreateFileMapping(map->hFile, NULL, PAGE_READWRITE, 0, size, NULL);
		if (map->hMap) {
			map->lpFileBuf = (BYTE*)MapViewOfFile(map->hMap, FILE_MAP_WRITE, 0, 0, size);
			if (map->lpFileBuf) {
				return TRUE;
			}
		}
	}

	NR2_CloseFileMap(map);
	return FALSE;
}

void NR2_CloseFileMap(FILEMAP* map)
{
	if (map->lpFileBuf) {
		UnmapViewOfFile(map->lpFileBuf);
		map->lpFileBuf = NULL;
	}
	if (map->hMap) {
		CloseHandle(map->hMap);
		map->hMap = NULL;
	}
	if (map->hFile) {
		CloseHandle(map->hFile);
		map->hFile = NULL;
	}
}

BOOL NR2_PutFile(LPCSTR path, void* data, DWORD size)
{
	FILEMAP map = { 0 };

	if (!NR2_OpenFileMap(&map, path, size)) {
		NR2_ErrorMsg("错误:写入文件失败");
		return FALSE;
	}

	memcpy_s(map.lpFileBuf, size, data, size);
	NR2_CloseFileMap(&map);
	return TRUE;
}

BOOL NR2_UnpackFile(LPCSTR path, void* data, DWORD pack_size)
{
	DW_PACDATA* pacData = (DW_PACDATA*)data;
	FILEMAP map = { 0 };
	DWORD offset;
	DWORD total;
	DWORD i;

	if (pack_size < sizeof(DW_PACDATA)) {
		NR2_ErrorMsg("错误:文件大小无效");
		return FALSE;
	}

	if (pacData->magic != 0x1234) {
		NR2_ErrorMsg("错误:魔数错误");
		return FALSE;
	}

	if (!pacData->pack_cnt) {
		return TRUE;
	}

	total = 0;
	for (i = 0; i < pacData->pack_cnt; ++i) {
		total += pacData->info[i].unpack_size;
		offset = pacData->hdr_offset + pacData->info[i].pack_size + pacData->info[i].data_offset;
		if (!pacData->info[i].pack_size || !pacData->info[i].unpack_size || offset > pack_size) {
			NR2_ErrorMsg("错误:发现损坏的数据头");
			return FALSE;
		}
	}

	if (!NR2_OpenFileMap(&map, path, total)) {
		NR2_ErrorMsg("错误:写入文件失败");
		return FALSE;
	}

	NR2_Uncompress(pacData, map.lpFileBuf);
	NR2_CloseFileMap(&map);
	return TRUE;
}

static WORD pak_dic[NR2_DWTABLELEN * 2];
static WORD pak_hint[1 << NR2_DWHINTBITS][2];

typedef struct _UNPACKER
{
	const BYTE* src;
	DWORD k;
	DWORD m;
	DWORD tlen;
	DWORD dic[2][NR2_DWTABLELEN];
	DWORD hint[1 << NR2_DWHINTBITS];
	DWORD bits[1 << NR2_DWHINTBITS];
} UNPACKER;

int NR2_MakeDictionary(UNPACKER* pak)
{
	int r;

	if (!pak->m--) {
		pak->m = 7;
		pak->k = *pak->src++;
	}

	if ((pak->k >> pak->m) & 1) {
		r = pak->tlen++;
		pak->dic[0][r - 256] = NR2_MakeDictionary(pak);
		pak->dic[1][r - 256] = NR2_MakeDictionary(pak);
	}
	else {
		pak->k = (pak->k << 8) + *pak->src++;
		r = (pak->k >> pak->m) & 255;
	}
	return r;
}

void NR2_MakeHintTable(UNPACKER* pak)
{
	DWORD i, j, n, skip;

	for (i = 0; i < (1 << NR2_DWHINTBITS);) {
		n = 256;
		j = NR2_DWHINTBITS;
		do {
			j--;
			n = pak->dic[(i >> j) & 1][n - 256];
			if (n <= 255) {
				break;
			}
		} while (j);

		skip = i | ((1 << j) - 1);
		do {
			pak->hint[i] = n;
			pak->bits[i] = j;
		} while (i++ < skip);
	}
}

void __fastcall NR2_Uncompress(void* data, BYTE* buf)
{
	DW_PACDATA* pacData = (DW_PACDATA*)data;
	BYTE* dst, * dst_max;
	const BYTE* src;
	DWORD i, n, hint;
	UNPACKER pak;

	dst = buf;
	src = (const BYTE*)pacData + pacData->hdr_offset;

	for (i = 0; i < pacData->pack_cnt; ++i) {
		ZeroMemory(&pak, sizeof(UNPACKER));
		pak.m = 0;
		pak.k = 0;
		pak.tlen = 256;
		pak.src = src + pacData->info[i].data_offset;
		n = NR2_MakeDictionary(&pak);

		if (n <= 255) {
			memset(dst, (BYTE)n, pacData->info[i].unpack_size);
			dst += pacData->info[i].unpack_size;
			continue;
		}

		NR2_MakeHintTable(&pak);

		if ((size_t)pak.src & 1) {
			pak.k = (pak.k << 8) + *pak.src++;
			pak.m += 8;
		}

		dst_max = dst + pacData->info[i].unpack_size;
		for (; dst < dst_max;) {
			if (pak.m < NR2_DWHINTBITS) {
				pak.k <<= 16;
				pak.m += 16;
				pak.k += _byteswap_ushort(*(const unsigned short*)pak.src);
				pak.src += 2;
			}

			pak.m -= NR2_DWHINTBITS;
			hint = (pak.k >> pak.m) & ((1 << NR2_DWHINTBITS) - 1);
			pak.m += pak.bits[hint];
			n = pak.hint[hint];
			for (; n > 255; n = pak.dic[(pak.k >> pak.m) & 1][n - 256]) {
				if (!pak.m--) {
					pak.m = 15;
					pak.k = _byteswap_ushort(*(const unsigned short*)pak.src);
					pak.src += 2;
				}
			}
			*dst++ = (BYTE)n;
		}
	}
}