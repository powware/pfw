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

#pragma warning(push, 0)

#include <Dwmapi.h>
#include <Ntstatus.h>
#include <TlHelp32.h>
#include <Windows.h>

#pragma warning(pop)

#include "detail/hooking.h"
#include "detail/winternal.h"

namespace pfw
{

	// always holds a valid handle
	class Handle
	{
	public:
		static std::optional<Handle> Create(HANDLE handle)
		{
			return handle == INVALID_HANDLE_VALUE ? std::nullopt : std::make_optional(Handle(handle));
		}

		~Handle()
		{
			if (handle_ != INVALID_HANDLE_VALUE) // only invalid after move operations
			{
				CloseHandle(handle_);
			}
		}

		Handle() = delete;
		Handle(const Handle &) = delete;
		Handle &operator=(const Handle &) = delete;

		Handle(Handle &&rhs) : Handle(rhs.handle_)
		{
			rhs.handle_ = INVALID_HANDLE_VALUE;
		}

		Handle &operator=(Handle &&rhs) noexcept
		{
			handle_ = rhs.handle_;
			rhs.handle_ = INVALID_HANDLE_VALUE;
		}

		auto operator*() const noexcept
		{
			return handle_;
		}

		auto get() const noexcept
		{
			return handle_;
		}

		operator HANDLE() const noexcept
		{
			return handle_;
		}

	private:
		HANDLE handle_;

		Handle(HANDLE handle) : handle_(handle) {}
	};

	inline std::optional<std::wstring> GenerateUUID()
	{
		UUID uuid;
		RPC_WSTR uuid_string;
		if (UuidCreate(&uuid))
		{
			return std::nullopt;
		}
		if (UuidToStringW(&uuid, &uuid_string))
		{
			return std::nullopt;
		}
		std::wstring result(reinterpret_cast<wchar_t *>(uuid_string));
		RpcStringFreeW(&uuid_string);
		return result;
	}

	inline bool SetDebugPrivileges()
	{
		const auto current_process = GetCurrentProcess(); // pseudo handle no need for closing
		const auto access_token = [current_process]()
		{
			HANDLE access_token;
			const auto success = OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, &access_token);
			return success ? Handle::Create(access_token) : std::nullopt;
		}();
		if (!access_token)
		{
			return false;
		}

		LUID luid;
		if (!LookupPrivilegeValueW(nullptr, L"seDebugPrivilege", &luid))
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

	inline std::optional<DWORD> GetProcessId(std::wstring_view process_name)
	{
		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof(PROCESSENTRY32);
		auto process_snapshot = Handle::Create(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (!process_snapshot)
		{
			return std::nullopt;
		}

		if (!Process32FirstW(*process_snapshot, &process_entry))
		{
			return std::nullopt;
		}
		do
		{
			if (process_name.compare(reinterpret_cast<const wchar_t *>(process_entry.szExeFile)) == 0)
			{
				return std::make_optional(process_entry.th32ProcessID);
			}
		} while (Process32NextW(process_snapshot->get(), &process_entry));

		return std::nullopt;
	}

	inline std::optional<std::wstring> GetExecutablePathFromProcessId(DWORD process_id)
	{
		MODULEENTRY32 module_entry;
		const auto module_snapshot = Handle::Create(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id));
		if (!module_snapshot)
		{
			return std::nullopt;
		}

		module_entry.dwSize = sizeof(MODULEENTRY32);

		if (!Module32FirstW(*module_snapshot, &module_entry))
		{
			return std::nullopt;
		}

		return module_entry.szExePath;
	}

	inline std::wstring GetModuleFileName(HMODULE module)
	{

		std::wstring executable(MAX_PATH, L'\0');
		auto size = GetModuleFileNameW(module, executable.data(), executable.size());
		executable.resize(size);
		return executable;
	}

	inline std::optional<Handle> OpenProcess(DWORD process_id, DWORD access = PROCESS_ALL_ACCESS)
	{
		return Handle::Create(::OpenProcess(access, false, process_id));
	}

	struct Process
	{
		Handle process;
		Handle thread;
	};

	inline std::optional<Process> CreateProcess(std::wstring executable, SECURITY_ATTRIBUTES *security_attributes, STARTUPINFO &startup_info)
	{
		PROCESS_INFORMATION process_info;
		if (!::CreateProcessW(executable.c_str(), nullptr, security_attributes, nullptr, true, CREATE_NO_WINDOW, nullptr, nullptr, &startup_info, &process_info))
		{
			return std::nullopt;
		}

		return Process(*pfw::Handle::Create(process_info.hProcess), *pfw::Handle::Create(process_info.hThread));
	}

	inline std::optional<bool> IsProcess32bit(DWORD process_id)
	{
		auto process = pfw::OpenProcess(process_id, PROCESS_QUERY_LIMITED_INFORMATION);
		if (!process)
		{
			return std::nullopt;
		}

		BOOL is_32bit;
		if (!IsWow64Process(*process, &is_32bit))
		{
			return std::nullopt;
		}

		return is_32bit;
	}

	inline bool GetRemoteMemory(HANDLE process_handle, void *destination, const void *source, std::size_t size)
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
	inline std::optional<Type> GetRemoteMemory(HANDLE process_handle, const void *source)
	{
		Type memory;
		return GetRemoteMemory(process_handle, &memory, source, sizeof(Type)) ? std::make_optional<Type>(memory) : std::nullopt;
	}

	inline std::optional<std::string> GetRemoteString(HANDLE process_handle, const void *source)
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
			else if (c == '\0')
			{
				return result;
			}

			result.push_back(*c);
		}
	}

	inline bool SetRemoteMemory(HANDLE process_handle, void *destination, const void *source, std::size_t size)
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

	inline std::optional<HMODULE> GetRemoteModuleHandle(HANDLE process_handle, std::wstring module_name)
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
		while (list_entry_pointer != reinterpret_cast<LIST_ENTRY *>(reinterpret_cast<unsigned char *>(peb.Ldr) + offsetof(PEB_LDR_DATA, InLoadOrderModuleList)))
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

	inline std::optional<void *> GetRemoteProcAddress(HANDLE process_handle, HMODULE module_handle, std::variant<std::string_view, WORD> name_or_ordinal) // procedure names are stored in ASCII
	{
		IMAGE_DOS_HEADER dos_header;
		if (!GetRemoteMemory(process_handle, &dos_header, module_handle, sizeof(dos_header)))
		{
			return std::nullopt;
		}

		IMAGE_NT_HEADERS nt_headers;
		if (!GetRemoteMemory(process_handle, &nt_headers, reinterpret_cast<unsigned char *>(module_handle) + dos_header.e_lfanew, sizeof(nt_headers)))
		{
			return std::nullopt;
		}

		IMAGE_EXPORT_DIRECTORY export_directory;
		if (!GetRemoteMemory(process_handle, &export_directory, reinterpret_cast<unsigned char *>(module_handle) + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(export_directory)))
		{
			return std::nullopt;
		}

		const std::optional<WORD> ordinal = [&]() -> std::optional<WORD>
		{
			if (std::holds_alternative<WORD>(name_or_ordinal))
			{
				return std::get<WORD>(name_or_ordinal);
			}

			std::vector<DWORD> name_offsets(export_directory.NumberOfNames);
			if (!GetRemoteMemory(process_handle, name_offsets.data(), reinterpret_cast<unsigned char *>(module_handle) + export_directory.AddressOfNames, name_offsets.size() * sizeof(DWORD)))
			{
				return std::nullopt;
			}

			const auto &name = std::get<std::string_view>(name_or_ordinal);
			for (std::size_t lhs = 0, rhs = name_offsets.size(); lhs != rhs;)
			{
				auto middle = lhs + (rhs - lhs) / 2; // prevents overflow compared to (lhs + rhs) / 2
				auto entry_name = GetRemoteString(process_handle, reinterpret_cast<unsigned char *>(module_handle) + name_offsets[middle]);
				if (!entry_name)
				{
					return std::nullopt;
				}

				auto comparison = name.compare(*entry_name);
				if (comparison == 0)
				{
					auto ordinal = GetRemoteMemory<WORD>(process_handle, reinterpret_cast<WORD *>(reinterpret_cast<unsigned char *>(module_handle) + export_directory.AddressOfNameOrdinals) + middle);
					if (!ordinal)
					{
						return std::nullopt;
					}

					return ordinal;
				}
				else if (comparison > 0)
				{
					lhs = middle + 1;
				}
				else if (comparison < 0)
				{
					rhs = middle;
				}
			}

			return std::nullopt;
		}();

		if (ordinal)
		{
			auto procedure_offset = GetRemoteMemory<DWORD>(process_handle, reinterpret_cast<DWORD *>(reinterpret_cast<unsigned char *>(module_handle) + export_directory.AddressOfFunctions) + *ordinal);
			if (!procedure_offset)
			{
				return std::nullopt;
			}

			return reinterpret_cast<unsigned char *>(module_handle) + *procedure_offset;
		}

		return std::nullopt;
	}
}

#endif // __PFW_H__