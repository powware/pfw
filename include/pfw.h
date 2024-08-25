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

	std::optional<HandleGuard> OpenProcess(DWORD process_id)
	{
		HANDLE process_handle = ::OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
		if (process_handle == INVALID_HANDLE_VALUE)
		{
			return std::nullopt;
		}

		return HandleGuard(process_handle);
	}

	class VirtualMemory
	{
	public:
		VirtualMemory(HANDLE process_handle, void *target_address, std::size_t size, DWORD allocation_type, DWORD protection, bool raii = true) : process_handle_(process_handle),
																																				  handle_(VirtualAllocEx(process_handle, target_address, size, allocation_type, protection)), size_(size), remote_(true), raii_(raii)
		{
			if (this->handle_ == nullptr)
				throw std::bad_alloc();
		};

		VirtualMemory(void *target_address, std::size_t size, DWORD allocation_type, DWORD protection) : process_handle_(GetCurrentProcess()),
																										 handle_(VirtualAlloc(target_address, size, allocation_type, protection)), size_(size), remote_(false), raii_(true)
		{
			if (this->handle_ == nullptr)
				throw std::bad_alloc();
		};

		~VirtualMemory()
		{
			if (this->handle_ && this->raii_)
			{
				if (this->remote_)
					VirtualFreeEx(process_handle_, handle_, 0, MEM_RELEASE);
				else
					VirtualFree(handle_, 0, MEM_RELEASE);
			}
		}
		template <typename T>
		operator T() const
		{
			return handle_;
		}

		void DisableRAII()
		{
			this->raii_ = false;
		}

	private:
		HANDLE handle_;
		HANDLE process_handle_;
		const std::size_t size_;
		const bool remote_;
		bool raii_;
	};

	void LoadLibrary(HANDLE process_handle, std::wstring dll_path)
	{
		VirtualMemory loader_memory(process_handle, nullptr, dll_path.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		HMODULE kernel_module = pfw::GetRemoteModuleHandle(process_handle, "Kernel32.dll");
		void *load_library = pfw::GetRemoteProcAddress(process_handle, kernel_module, "LoadLibraryW");
		pfw::stringutils::SetRemoteString(process_handle, loader_memory, this->dll_path_);
		pfw::RemoteThread loader_thread(process_handle, load_library, loader_memory);
		loader_thread.Join();
		// this->handle_ = loader_thread.GetExitCode();
	}

	void FreeLibrary()
	{
		pfw::ProcessHandle process_handle = process_.GetProcessHandle();
		VirtualMemory module_handle_memory(process_handle, nullptr, sizeof(HMODULE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		pfw::SetRemoteMemory(process_handle, module_handle_memory, this->handle_);
		HMODULE kernel_module = pfw::GetRemoteModuleHandle(process_handle, "Kernel32.dll");
		void *free_library = pfw::GetRemoteProcAddress(process_handle, kernel_module, "FreeLibrary");
		pfw::RemoteThread loader_thread(process_handle, free_library, module_handle_memory);
		loader_thread.Join();
	}
}

#endif // __PFW_H__