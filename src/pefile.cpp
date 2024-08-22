#include "pefile.h"

#include <stdexcept>

#include "pfwlib.h"

IMAGE_DOS_HEADER* pfw::pefile::GetDOSHeader(void* image_base)
{
	return static_cast<IMAGE_DOS_HEADER*>(image_base);
}

IMAGE_DOS_HEADER pfw::pefile::GetRemoteDOSHeader(HANDLE process_handle, void* image_base)
{
	return pfw::GetRemoteMemory(process_handle, static_cast<IMAGE_DOS_HEADER*>(image_base));
}

IMAGE_FILE_HEADER* pfw::pefile::GetPEHeader(void* image_base)
{
	return reinterpret_cast<IMAGE_FILE_HEADER*>(static_cast<char*>(image_base) + static_cast<IMAGE_DOS_HEADER*>(image_base)->e_lfanew + sizeof(LONG));
}

IMAGE_FILE_HEADER pfw::pefile::GetRemotePEHeader(HANDLE process_handle, void* image_base)
{
	return pfw::GetRemoteMemory(process_handle, reinterpret_cast<IMAGE_FILE_HEADER*>(static_cast<char*>(image_base) + pfw::pefile::GetRemoteDOSHeader(process_handle, image_base).e_lfanew + sizeof(LONG)));
}

LONG pfw::pefile::GetNTSignature(void* image_base)
{
	return *reinterpret_cast<LONG*>(static_cast<char*>(image_base) + pfw::pefile::GetDOSHeader(image_base)->e_lfanew);
}

WORD pfw::pefile::GetPEFormat(void* image_base)
{
	return *reinterpret_cast<WORD*>(reinterpret_cast<char*>(pfw::pefile::GetPEHeader(image_base)) + sizeof(IMAGE_FILE_HEADER));
}

IMAGE_SECTION_HEADER* pfw::pefile::GetSectionHeaderList(void* image_base)
{
	return reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<char*>(pfw::pefile::GetPEHeader(image_base)) + sizeof(IMAGE_FILE_HEADER) + pfw::pefile::GetPEHeader(image_base)->SizeOfOptionalHeader);
}

IMAGE_OPTIONAL_HEADER* pfw::pefile::GetOptionalHeader(void* image_base)
{
	return reinterpret_cast<IMAGE_OPTIONAL_HEADER*>(reinterpret_cast<char*>(pfw::pefile::GetPEHeader(image_base)) + sizeof(IMAGE_FILE_HEADER));
}

IMAGE_OPTIONAL_HEADER pfw::pefile::GetRemoteOptionalHeader(HANDLE process_handle, void* image_base)
{
	return pfw::GetRemoteMemory(process_handle, reinterpret_cast<IMAGE_OPTIONAL_HEADER*>(reinterpret_cast<char*>(static_cast<char*>(image_base) + pfw::GetRemoteMemory(process_handle, static_cast<IMAGE_DOS_HEADER*>(image_base)).e_lfanew + sizeof(LONG)) + sizeof(IMAGE_FILE_HEADER)));
}

IMAGE_DATA_DIRECTORY pfw::pefile::GetDataDirectory(void* image_base, unsigned int index)
{
	if (index >= pfw::pefile::GetOptionalHeader(image_base)->NumberOfRvaAndSizes)
		throw std::out_of_range("Index for DataDirectory out of range.");
	return pfw::pefile::GetOptionalHeader(image_base)->DataDirectory[index];
}

IMAGE_DATA_DIRECTORY pfw::pefile::GetRemoteDataDirectory(HANDLE process_handle, void* image_base, unsigned int index)
{
	if (index >= pfw::pefile::GetRemoteOptionalHeader(process_handle, image_base).NumberOfRvaAndSizes)
		throw std::out_of_range("Index for DataDirectory out of range.");
	return pfw::pefile::GetRemoteOptionalHeader(process_handle, image_base).DataDirectory[index];
}
