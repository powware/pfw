#ifndef __PFW_H__
#define __PFW_H__

#include <algorithm>
#include <cstdlib>
#include <cwctype>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>

#include <Dwmapi.h>
#include <Ntstatus.h>
#include <TlHelp32.h>
#include <Windows.h>

#include "detail/hooking.h"
#include "detail/winternal.h"

namespace pfw
{

	// always holds a valid handle
	class HandleGuard
	{
	public:
		static std::optional<HandleGuard> Create(HANDLE handle)
		{
			return handle == INVALID_HANDLE_VALUE ? std::nullopt : std::make_optional(HandleGuard(handle));
		}

		~HandleGuard()
		{
			if (handle_) // only invalid after move operations
			{
				CloseHandle(*handle_);
			}
		}

		HandleGuard() = delete;
		HandleGuard(const HandleGuard &) = delete;
		HandleGuard &operator=(const HandleGuard &) = delete;
		HandleGuard &operator=(HandleGuard &&) noexcept = delete;

		HandleGuard(HandleGuard &&rhs) : HandleGuard(*rhs.handle_)
		{
			rhs.handle_ = std::nullopt;
		}

		auto operator*() const noexcept
		{
			return *handle_;
		}

		auto get() const noexcept
		{
			return *handle_;
		}

		operator HANDLE() const noexcept
		{
			return *handle_;
		}

	private:
		std::optional<HANDLE> handle_;

		HandleGuard(HANDLE handle) : handle_(handle) {}
	};

	bool SetDebugPrivileges()
	{
		const auto current_process = GetCurrentProcess(); // pseudo handle no need for closing
		const auto access_token = [current_process]()
		{
			HANDLE access_token;
			const auto success = OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, &access_token);
			return success ? HandleGuard::Create(access_token) : std::nullopt;
		}();
		if (!access_token)
		{
			return false;
		}

		LUID luid;
		if (!LookupPrivilegeValue(nullptr, L"seDebugPrivilege", &luid))
		{
			return false;
		}

		TOKEN_PRIVILEGES token_privileges;
		token_privileges.PrivilegeCount = 1;
		token_privileges.Privileges[0].Luid = luid;
		token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		const auto success = AdjustTokenPrivileges(*access_token, false, &token_privileges, 0, nullptr, nullptr);
		const DWORD error_code = GetLastError();
		if (!success || error_code != ERROR_SUCCESS)
		{
			return false;
		};

		return true;
	}

	std::optional<DWORD> GetProcessId(std::wstring_view process_name)
	{
		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof(PROCESSENTRY32);
		auto process_snapshot = HandleGuard::Create(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (!process_snapshot)
		{
			return std::nullopt;
		}

		if (!Process32First(*process_snapshot, &process_entry))
		{
			return std::nullopt;
		}
		do
		{
			if (process_name.compare(reinterpret_cast<const wchar_t *>(process_entry.szExeFile)) == 0)
			{
				return std::make_optional(process_entry.th32ProcessID);
			}
		} while (Process32Next(process_snapshot->get(), &process_entry));

		return std::nullopt;
	}

	std::optional<std::wstring> ExecutablePathFromProcessId(DWORD process_id)
	{
		MODULEENTRY32 module_entry;
		const auto module_snapshot = HandleGuard::Create(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id));
		if (!module_snapshot)
		{
			return std::nullopt;
		}

		module_entry.dwSize = sizeof(MODULEENTRY32);

		if (!Module32First(*module_snapshot, &module_entry))
		{
			return std::nullopt;
		}

		return module_entry.szExePath;
	}

	std::optional<HandleGuard> OpenProcess(DWORD process_id, DWORD access = PROCESS_ALL_ACCESS)
	{
		return HandleGuard::Create(::OpenProcess(access, false, process_id));
	}

	bool GetRemoteMemory(HANDLE process_handle, void *destination, const void *source, std::size_t size)
	{
		SIZE_T size_read;
		auto success = ReadProcessMemory(process_handle, source, destination, size, &size_read);
		if (!success || size_read != size)
		{
			return false;
		}

		return true;
	}

	// template <typename TypePointer,
	// 		  typename = std::enable_if_t<std::is_pointer_v<TypePointer> &&
	// 									  !std::is_void_v<std::remove_pointer_t<TypePointer>>>>
	// auto GetRemoteMemory(HANDLE process_handle, const TypePointer source)
	// {
	// 	using Type = typename std::remove_const_t<std::remove_pointer_t<TypePointer>>;
	// 	Type memory;
	// 	auto success = GetRemoteMemory(process_handle, &memory, source, sizeof(Type));
	// 	return success ? std::optional<Type>(memory) : std::nullopt;
	// }

	template <typename Type>
	std::optional<Type> GetRemoteMemory(HANDLE process_handle, const void *source)
	{
		Type memory;
		return GetRemoteMemory(process_handle, &memory, source, sizeof(Type)) ? std::make_optional<Type>(memory) : std::nullopt;
	}

	std::optional<std::string> GetRemoteString(HANDLE process_handle, const void *source)
	{
		const char *iterator = static_cast<const char *>(source);

		std::string result;
		while (true)
		{
			auto c = GetRemoteMemory<char>(process_handle, static_cast<const char *>(source) + result.size());
			if (!c)
			{
				return std::nullopt;
			}
			if (c == '\0')
			{
				return result;
			}

			result.push_back(*c);
		}
	}

	bool SetRemoteMemory(HANDLE process_handle, void *destination, const void *source, std::size_t size)
	{
		SIZE_T size_written = 0;
		auto success = WriteProcessMemory(process_handle, destination, source, size, &size_written);
		if (!success || size_written != size)
		{
			return false;
		}

		return true;
	}

	// template <typename Type, typename = std::enable_if_t<std::is_same<Type, std::decay_t<Type>>::value>>
	// std::size_t SetRemoteMemory(HANDLE process_handle, void *address, const Type &value)
	// {
	// 	SIZE_T size_written = 0;
	// 	pfw::SetRemoteMemory(process_handle, address, &value, sizeof(Type));
	// 	return std::size_t(size_written);
	// }

	std::optional<HMODULE> GetRemoteModuleHandle(HANDLE process_handle, std::wstring module_name)
	{
		PROCESS_BASIC_INFORMATION process_basic_information;
		NTSTATUS status = NtQueryInformationProcess(process_handle, ProcessBasicInformation, &process_basic_information, sizeof(process_basic_information), NULL);
		if (status != STATUS_SUCCESS)
		{
			return std::nullopt;
		}

		PEB peb;
		if (!GetRemoteMemory(process_handle, &peb, process_basic_information.PebBaseAddress, sizeof(peb)))
		{
			return std::nullopt;
		}

		PEB_LDR_DATA loader_data;
		if (!GetRemoteMemory(process_handle, &loader_data, peb.Ldr, sizeof(loader_data)))
		{
			return std::nullopt;
		}

		const auto to_lower = [](std::wstring &s)
		{ std::for_each(s.begin(), s.end(), [](auto &c)
						{ c = std::towlower(c); }); };

		to_lower(module_name);

		LIST_ENTRY *list_entry_pointer = loader_data.InLoadOrderModuleList.Flink;
		while (list_entry_pointer != reinterpret_cast<LIST_ENTRY *>(reinterpret_cast<char *>(peb.Ldr) + offsetof(PEB_LDR_DATA, InLoadOrderModuleList)))
		{
			LDR_DATA_TABLE_ENTRY table_entry;
			GetRemoteMemory(process_handle, &table_entry, list_entry_pointer, sizeof(table_entry));

			std::wstring dll_name;
			dll_name.resize(table_entry.BaseDllName.Length / sizeof(wchar_t));
			GetRemoteMemory(process_handle, dll_name.data(), table_entry.BaseDllName.Buffer, dll_name.size() * sizeof(wchar_t));

			to_lower(dll_name);
			if (dll_name.compare(module_name) == 0)
			{
				return reinterpret_cast<HMODULE>(table_entry.DllBase);
			}

			list_entry_pointer = table_entry.InLoadOrderLinks.Flink;
		}

		return std::nullopt;
	}

	std::optional<void *> GetRemoteProcAddress(HANDLE process_handle, HMODULE module_handle, std::variant<std::string_view, WORD> name_or_ordinal) // procedure names are stored in ASCII
	{
		IMAGE_DOS_HEADER dos_header;
		if (!GetRemoteMemory(process_handle, &dos_header, module_handle, sizeof(dos_header)))
		{
			return std::nullopt;
		}

		IMAGE_NT_HEADERS nt_headers;
		if (!GetRemoteMemory(process_handle, &nt_headers, reinterpret_cast<char *>(module_handle) + dos_header.e_lfanew, sizeof(nt_headers)))
		{
			return std::nullopt;
		}

		IMAGE_EXPORT_DIRECTORY export_directory;
		if (!GetRemoteMemory(process_handle, &export_directory, reinterpret_cast<char *>(module_handle) + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(export_directory)))
		{
			return std::nullopt;
		}

		const std::optional<WORD> ordinal = [&]() -> std::optional<WORD>
		{
			if (std::holds_alternative<std::string_view>(name_or_ordinal))
			{
				std::vector<DWORD> name_offsets(export_directory.NumberOfNames);
				if (!GetRemoteMemory(process_handle, name_offsets.data(), reinterpret_cast<char *>(module_handle) + export_directory.AddressOfNames, name_offsets.size() * sizeof(DWORD)))
				{
					return std::nullopt;
				}

				std::size_t lhs = 0;
				std::size_t rhs = name_offsets.size();
				while (true)
				{
					auto middle = (lhs + rhs) / 2;
					auto entry_name = GetRemoteString(process_handle, reinterpret_cast<char *>(module_handle) + name_offsets[middle]);
					if (!entry_name)
					{
						return std::nullopt;
					}
					auto comparison = std::get<std::string_view>(name_or_ordinal).compare(*entry_name);
					if (comparison == 0)
					{
						auto ordinal = GetRemoteMemory<WORD>(process_handle, reinterpret_cast<WORD *>(reinterpret_cast<char *>(module_handle) + export_directory.AddressOfNameOrdinals) + middle);
						if (!ordinal)
						{
							return std::nullopt;
						}
						return ordinal;
					}
					else if (lhs == rhs)
					{
						return std::nullopt;
					}
					else if (comparison > 0)
					{
						lhs = middle;
					}
					else if (comparison < 0)
					{
						rhs = middle;
					}
				}

				return std::nullopt;
			}
			else
			{
				return std::get<WORD>(name_or_ordinal);
			}
		}();

		if (ordinal)
		{
			DWORD procedure_offset;
			if (!GetRemoteMemory(process_handle, &procedure_offset, reinterpret_cast<DWORD *>(reinterpret_cast<char *>(module_handle) + export_directory.AddressOfFunctions) + *ordinal, sizeof(DWORD)))
			{
				return std::nullopt;
			}
			return reinterpret_cast<char *>(module_handle) + procedure_offset;
		}

		return std::nullopt;
	}
}

#endif // __PFW_H__