#ifndef __PEFILE_H__
#define __PEFILE_H__

#include <Windows.h>

#include "pfw.h"

namespace pfw::internal
{
	IMAGE_DOS_HEADER *GetDOSHeader(void *image_base)
	{
		return static_cast<IMAGE_DOS_HEADER *>(image_base);
	}

	IMAGE_DOS_HEADER GetRemoteDOSHeader(HANDLE process_handle, void *image_base)
	{
		return pfw::GetRemoteMemory(process_handle, static_cast<IMAGE_DOS_HEADER *>(image_base));
	}

	IMAGE_FILE_HEADER *GetPEHeader(void *image_base)
	{
		return reinterpret_cast<IMAGE_FILE_HEADER *>(static_cast<char *>(image_base) + static_cast<IMAGE_DOS_HEADER *>(image_base)->e_lfanew + sizeof(LONG));
	}

	IMAGE_FILE_HEADER GetRemotePEHeader(HANDLE process_handle, void *image_base)
	{
		return pfw::GetRemoteMemory(process_handle, reinterpret_cast<IMAGE_FILE_HEADER *>(static_cast<char *>(image_base) + GetRemoteDOSHeader(process_handle, image_base).e_lfanew + sizeof(LONG)));
	}

	LONG GetNTSignature(void *image_base)
	{
		return *reinterpret_cast<LONG *>(static_cast<char *>(image_base) + GetDOSHeader(image_base)->e_lfanew);
	}

	WORD GetPEFormat(void *image_base)
	{
		return *reinterpret_cast<WORD *>(reinterpret_cast<char *>(GetPEHeader(image_base)) + sizeof(IMAGE_FILE_HEADER));
	}

	IMAGE_SECTION_HEADER *GetSectionHeaderList(void *image_base)
	{
		return reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<char *>(GetPEHeader(image_base)) + sizeof(IMAGE_FILE_HEADER) + GetPEHeader(image_base)->SizeOfOptionalHeader);
	}

	IMAGE_OPTIONAL_HEADER *GetOptionalHeader(void *image_base)
	{
		return reinterpret_cast<IMAGE_OPTIONAL_HEADER *>(reinterpret_cast<char *>(GetPEHeader(image_base)) + sizeof(IMAGE_FILE_HEADER));
	}

	IMAGE_OPTIONAL_HEADER GetRemoteOptionalHeader(HANDLE process_handle, void *image_base)
	{
		return pfw::GetRemoteMemory(process_handle, reinterpret_cast<IMAGE_OPTIONAL_HEADER *>(reinterpret_cast<char *>(static_cast<char *>(image_base) + pfw::GetRemoteMemory(process_handle, static_cast<IMAGE_DOS_HEADER *>(image_base)).e_lfanew + sizeof(LONG)) + sizeof(IMAGE_FILE_HEADER)));
	}

	IMAGE_DATA_DIRECTORY GetDataDirectory(void *image_base, unsigned int index)
	{
		return GetOptionalHeader(image_base)->DataDirectory[index];
	}

	IMAGE_DATA_DIRECTORY GetRemoteDataDirectory(HANDLE process_handle, void *image_base, unsigned int index)
	{
		return GetRemoteOptionalHeader(process_handle, image_base).DataDirectory[index];
	}

}
#endif // __PEFILE_H__