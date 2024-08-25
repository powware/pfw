#ifndef __PFW_H__
#define __PFW_H__

#include <cstdlib>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include <Dwmapi.h>
#include <TlHelp32.h>
#include <Windows.h>

#include "detail/hooking.h"

namespace pfw
{

	struct HandleCloser
	{
		void operator()(HANDLE h) const
		{
			if (h && h != INVALID_HANDLE_VALUE)
			{
				CloseHandle(h);
			}
		}
	};

	using HandleGuard = std::unique_ptr<void, HandleCloser>;

	// class HandleGuard
	// {
	// public:
	// 	HandleGuard(HANDLE handle) : handle_(handle) {}
	// 	~HandleGuard()
	// 	{
	// 		CloseHandle(handle_);
	// 	}

	// 	operator HANDLE()
	// 	{
	// 		return handle_;
	// 	}

	// private:
	// 	HANDLE handle_;
	// };

	bool
	SetDebugPrivileges()
	{
		HANDLE current_process = GetCurrentProcess(); // pseudo handle no need for closing
		HANDLE access_token;
		auto success = OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, &access_token);
		if (!success || access_token == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		HandleGuard access_token_guard(access_token);

		LUID luid;
		if (!LookupPrivilegeValue(nullptr, L"seDebugPrivilege", &luid))
		{
			return false;
		}

		TOKEN_PRIVILEGES token_privileges;
		token_privileges.PrivilegeCount = 1;
		token_privileges.Privileges[0].Luid = luid;
		token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		success = AdjustTokenPrivileges(access_token, false, &token_privileges, 0, nullptr, nullptr);
		DWORD error_code = GetLastError();
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
		auto process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (process_snapshot == INVALID_HANDLE_VALUE)
		{
			return std::nullopt;
		}
		HandleGuard process_snapshot_guard(process_snapshot);

		if (!Process32First(process_snapshot, &process_entry))
		{
			return std::nullopt;
		}
		do
		{
			if (process_name.compare(reinterpret_cast<const wchar_t *>(process_entry.szExeFile)) == 0)
			{
				return std::make_optional(process_entry.th32ProcessID);
			}
		} while (Process32Next(process_snapshot, &process_entry));

		return std::nullopt;
	}

	// class ProcessHandle
	// {
	// public:
	// 	ProcessHandle(DWORD process_id)
	// 	{
	// 		HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
	// 		if (process_handle == INVALID_HANDLE_VALUE)
	// 			throw std::runtime_error("derive this error");
	// 		return process_handle;
	// 	}
	// 	ProcessHandle(std::wstring_view process_name) : ProcessHandle(GetProcessId(process_name)) {}

	// 	~ProcessHandle()
	// 	{
	// 		CloseHandle(handle_);
	// 	}

	// 	operator HANDLE()
	// 	{
	// 		return handle_;
	// 	}

	// private:
	// 	HANDLE handle_;
	// };
}

#endif // __PFW_H__