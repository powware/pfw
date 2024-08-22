#pragma once

#include <Windows.h>

namespace pfw::pefile
{
	IMAGE_DOS_HEADER* GetDOSHeader(void* image_base);
	IMAGE_DOS_HEADER GetRemoteDOSHeader(HANDLE process_handle, void* image_base);

	IMAGE_FILE_HEADER* GetPEHeader(void* image_base);
	IMAGE_FILE_HEADER GetRemotePEHeader(HANDLE process_handle, void* image_base);

	LONG GetNTSignature(void* image_base);

	WORD GetPEFormat(void* image_base);

	IMAGE_OPTIONAL_HEADER* GetOptionalHeader(void* image_base);
	IMAGE_OPTIONAL_HEADER GetRemoteOptionalHeader(HANDLE process_handle, void* image_base);

	IMAGE_SECTION_HEADER* GetSectionHeaderList(void* image_base);

	IMAGE_DATA_DIRECTORY GetDataDirectory(void* image_base, unsigned int index);
	IMAGE_DATA_DIRECTORY GetRemoteDataDirectory(HANDLE process_handle, void* image_base, unsigned int index);

}