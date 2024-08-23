#ifndef __STRINGUTILS_H__
#define __STRINGUTILS_H__

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

#include <Windows.h>

namespace pfw
{

	std::string WStringToString(std::wstring_view wstring_view)
	{
		const int length = WideCharToMultiByte(CP_UTF8, NULL, wstring_view.data(), wstring_view.size(), nullptr, 0, nullptr, nullptr);
		char *cstring = new char[length];
		WideCharToMultiByte(CP_UTF8, NULL, wstring_view.data(), wstring_view.size(), cstring, length, nullptr, nullptr);
		std::string string(cstring);
		delete[] cstring;
		return string;
	}

	std::wstring StringToWString(std::string_view string_view)
	{
		const int length = MultiByteToWideChar(CP_UTF8, NULL, string_view.data(), string_view.size(), nullptr, 0);
		wchar_t *wcstring = new wchar_t[length];
		MultiByteToWideChar(CP_UTF8, NULL, string_view.data(), string_view.size(), wcstring, length);
		std::wstring wstring(wcstring);
		delete[] wcstring;
		return wstring;
	}

	std::size_t CaseInsensitiveFind(std::string_view searched_in, std::string_view searched_for)
	{
		auto position = std::search(searched_in.begin(), searched_in.end(), searched_for.begin(), searched_for.end(), [](char char1, char char2)
									{ return std::toupper(char1) == std::toupper(char2); });
		return position != searched_in.end() ? position - searched_in.begin() : std::string::npos;
	}

	std::vector<std::string> Split(std::string string, std::string_view delimeter)
	{
		std::vector<std::string> results;
		std::size_t position = string.find(delimeter.data());
		while (position != std::string::npos)
		{
			results.push_back(string.substr(0, position));
			string.erase(0, position + delimeter.size());
			position = string.find(delimeter.data());
		}
		results.push_back(string);
		return results;
	}

	std::size_t GetRemoteStringLength(HANDLE process_handle, const void *source)
	{
		std::size_t length = 0;
		while (GetRemoteMemory(process_handle, static_cast<const char *>(source) + length++))
			;
		return length;
	}

	std::string GetRemoteString(HANDLE process_handle, const void *source)
	{
		const char *iterator = static_cast<const char *>(source);

		std::string result;
		for (char current = GetRemoteMemory(process_handle, iterator++); current; current = GetRemoteMemory(process_handle, iterator++))
		{
			result += current;
		}
		return result;
	}

	std::size_t SetRemoteString(HANDLE process_handle, void *destination, std::string_view string_view)
	{
		return SetRemoteMemory(process_handle, destination, string_view.data(), string_view.size());
	}

	std::string GetFileNameFromPath(std::string path)
	{
		auto results = Split(std::forward<std::string>(path), "\\");
		return results[results.size() - 1];
	}

}

#endif // __STRINGUTILS_H__