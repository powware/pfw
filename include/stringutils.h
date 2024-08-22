#pragma once

#include <Windows.h>

#include <cstdlib>
#include <string>
#include <vector>

namespace pfw::stringutils
{
	std::string WStringToString(std::wstring_view wstring_view);

	std::wstring StringToWString(std::string_view string_view);

	std::size_t CaseInsensitiveFind(std::string_view searched_in, std::string_view searched_for);

	std::vector<std::string> Split(std::string string, std::string_view delimeter);

	std::size_t GetRemoteStringLength(HANDLE process_handle, const void* source);

	std::string GetRemoteString(HANDLE process_handle, const void* source);

	std::size_t SetRemoteString(HANDLE process_handle, void* destination, std::string_view string_view);

	std::string GetFileNameFromPath(std::string path);
}
