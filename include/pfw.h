#ifndef __PFW_H__
#define __PFW_H__

#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>

#include <Dwmapi.h>
#include <TlHelp32.h>
#include <Windows.h>

#include "detail/hooking.h"

namespace pfw
{
	class Handle
	{
	public:
		Handle(HANDLE handle) : handle_(handle) {}
		~Handle()
		{
			CloseHandle(handle_);
		}

		operator HANDLE()
		{
			return handle_;
		}

	private:
		HANDLE handle_;
	};

	Handle MakeValidHandle(HANDLE handle)
	{
		if (handle == INVALID_HANDLE_VALUE)
		{
			throw std::runtime_error("derive this error");
		}
		return Handle(handle);
	}

	void SetDebugPrivileges()
	{
		HANDLE current_process = GetCurrentProcess();
		HANDLE temp_handle;
		OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, &temp_handle);
		auto access_token = MakeValidHandle(temp_handle);
		LUID luid;
		LookupPrivilegeValueW(nullptr, L"seDebugPrivilege", &luid);
		TOKEN_PRIVILEGES token_privileges;
		token_privileges.PrivilegeCount = 1;
		token_privileges.Privileges[0].Luid = luid;
		token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bool result = AdjustTokenPrivileges(access_token, false, &token_privileges, 0, nullptr, nullptr);
		DWORD error_code = GetLastError();
		if (!result || error_code != ERROR_SUCCESS)
		{
			throw std::runtime_error("derive this error");
		};
	}

	DWORD GetProcessId(std::wstring_view process_name)
	{
		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof(PROCESSENTRY32);
		auto process_snapshot = MakeValidHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

		if (!Process32First(process_snapshot, &process_entry))
		{
			throw std::runtime_error("derive this error");
		}
		do
		{
			if (process_name.compare(reinterpret_cast<const wchar_t *>(process_entry.szExeFile)) == 0)
			{
				return process_entry.th32ProcessID;
			}
		} while (Process32Next(process_snapshot, &process_entry));
		throw std::runtime_error("derive this error");
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