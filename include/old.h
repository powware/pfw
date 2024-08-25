#ifndef __PFWLIB_H__
#define __PFWLIB_H__

#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>

#include <Dwmapi.h>
#include <TlHelp32.h>
#include <Windows.h>

#include "detail/hooking.h"
#include "detail/pefile.h"
#include "detail/stringutils.h"
#include "detail/windows_extensions.h"

namespace pfw
{
	struct Module
	{
		HANDLE process_handle = INVALID_HANDLE_VALUE;
		void *base = nullptr;
		std::size_t base_size = NULL;

		DWORD_PTR operator+(DWORD offset)
		{
			return reinterpret_cast<DWORD_PTR>(static_cast<char *>(this->base) + offset);
		}
	};

	class VirtualMemory
	{
	public:
		VirtualMemory(void *target_address, std::size_t size, DWORD allocation_type, DWORD protection) : size_(size),
																										 handle_(std::shared_ptr<HANDLE>(static_cast<HANDLE *>(VirtualAlloc(target_address, size, allocation_type, protection)), [](HANDLE h)
																																		 { VirtualFree(h, 0, MEM_RELEASE); }))
		{
			if (this->handle_ == nullptr)
				throw std::bad_alloc();
		}

		template <typename T>
		operator T() const
		{
			return handle_;
		}

	private:
		std::size_t size_;
		std::shared_ptr<HANDLE> handle_;
	};

	class RemoteVirtualMemory
	{
	public:
		RemoteVirtualMemory(HANDLE process_handle, void *target_address, std::size_t size, DWORD allocation_type, DWORD protection) : process_handle_(process_handle), size_(size),
																																	  handle_(VirtualAllocEx(process_handle, target_address, size, allocation_type, protection))
		{
			if (this->handle_ == nullptr)
				throw std::bad_alloc();
		}

		void Release()
		{
			VirtualFreeEx(process_handle_, handle_, 0, MEM_RELEASE);
			process_handle_ = nullptr;
			size_ = 0;
			handle_ = nullptr;
		}

		template <typename T>
		operator T() const
		{
			return handle_;
		}

	private:
		HANDLE process_handle_;
		std::size_t size_;
		HANDLE handle_;
	};

	std::string GetLastErrorString()
	{
		DWORD error_code = GetLastError();
		std::string error_string;
		if (error_code)
		{
			char *error_cstring;
			DWORD error_cstring_length = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char *)&error_cstring, 0, nullptr);
			if (error_cstring_length)
			{
				error_string = {error_cstring, error_cstring_length};
				LocalFree(error_cstring);
			}
		}
		return error_string;
	}

	void SetDebugPrivileges()
	{
		HANDLE CurrentProcess = GetCurrentProcess();
		HANDLE AccessToken;
		TOKEN_PRIVILEGES TokenPrivileges;
		LUID LocalUniqueIdentifier;
		OpenProcessToken(CurrentProcess, TOKEN_ADJUST_PRIVILEGES, &AccessToken);
		LookupPrivilegeValue(0, "seDebugPrivilege", &LocalUniqueIdentifier);
		TokenPrivileges.PrivilegeCount = 1;
		TokenPrivileges.Privileges[0].Luid = LocalUniqueIdentifier;
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bool result = AdjustTokenPrivileges(AccessToken, false, &TokenPrivileges, 0, 0, 0);
		DWORD error_code = GetLastError();
		CloseHandle(AccessToken);
		if (!result || error_code != ERROR_SUCCESS)
		{
			throw std::runtime_error("derive this error");
		};
	}

	DWORD GetProcessId(std::string_view process_name)
	{
		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof(PROCESSENTRY32);
		HANDLE processSnapShotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (processSnapShotHandle == INVALID_HANDLE_VALUE)
			return 0;
		if (!Process32First(processSnapShotHandle, &process_entry))
		{
			CloseHandle(processSnapShotHandle);
			return 0;
		}
		do
		{
			if (!_stricmp(process_entry.szExeFile, process_name.data()))
			{
				CloseHandle(processSnapShotHandle);
				return process_entry.th32ProcessID;
			}
		} while (Process32Next(processSnapShotHandle, &process_entry));
		CloseHandle(processSnapShotHandle);
		throw std::runtime_error("derive this error");
	}

	HANDLE GetProcessHandle(DWORD process_id)
	{
		HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
		if (process_handle == nullptr)
			throw std::runtime_error("derive this error");
		return process_handle;
	}

	HANDLE GetProcessHandle(std::string_view process_name)
	{
		return pfw::GetProcessHandle(GetProcessId(process_name));
	}

	class ProcessHandle
	{
	public:
		ProcessHandle(DWORD process_id) : handle_(pfw::GetProcessHandle(process_id)) {}

		~ProcessHandle()
		{
			CloseHandle(this->handle_);
		}

		template <typename T>
		operator T()
		{
			return this->handle_;
		}

	private:
		HANDLE handle_;
	};

	pfw::PEB GetRemotePEB(HANDLE process_handle)
	{
		PROCESS_BASIC_INFORMATION process_basic_information;
		NTSTATUS status = NtQueryInformationProcess(process_handle, ProcessBasicInformation, &process_basic_information, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		if (status)
		{
			throw std::runtime_error("derive this error");
		}
		return pfw::GetRemoteMemory(process_handle, reinterpret_cast<pfw::PEB *>(process_basic_information.PebBaseAddress));
	}

	HMODULE GetRemoteModuleHandle(HANDLE process_handle, std::string_view module_name)
	{
		pfw::PEB process_environment_block = pfw::GetRemotePEB(process_handle);
		pfw::PEB_LDR_DATA loader_data = pfw::GetRemoteMemory(process_handle, process_environment_block.Ldr);
		LIST_ENTRY list_head = loader_data.InLoadOrderModuleList;
		LIST_ENTRY *list_entry_pointer = list_head.Flink;
		while (list_entry_pointer != reinterpret_cast<LIST_ENTRY *>(reinterpret_cast<char *>(process_environment_block.Ldr) + (reinterpret_cast<char *>(&loader_data.InLoadOrderModuleList) - reinterpret_cast<char *>(&loader_data))))
		{
			pfw::LoaderDataTableEntry table_entry = pfw::GetRemoteMemory(process_handle, reinterpret_cast<pfw::LoaderDataTableEntry *>(list_entry_pointer));

			std::size_t length = table_entry.BaseDllName.Length / sizeof(wchar_t);
			std::vector<wchar_t> dll_name_wcstring(length + 1);
			pfw::GetRemoteMemory(process_handle, table_entry.BaseDllName.Buffer, dll_name_wcstring.data(), table_entry.BaseDllName.Length);
			dll_name_wcstring[length] = '\0';
			std::string dll_name = pfw::stringutils::WStringToString({dll_name_wcstring.data(), dll_name_wcstring.size()});

			if (pfw::stringutils::CaseInsensitiveFind(dll_name, module_name) != std::string::npos)
				return static_cast<HMODULE>(table_entry.DllBase);

			list_entry_pointer = table_entry.InLoadOrderLinks.Flink;
		}
		throw std::runtime_error("derive this error");
	}

	void *pfw::GetRemoteProcAddress(HANDLE process_handle, HMODULE module_handle, const char *procedure_name)
	{
		struct HighLowWord
		{
#ifdef _WIN64
			DWORD padding;
#endif
			WORD high_word;
			WORD ordinal;
		};

		IMAGE_EXPORT_DIRECTORY export_directory = pfw::GetRemoteMemory(process_handle, reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(reinterpret_cast<char *>(module_handle) + pfw::pefile::GetRemoteDataDirectory(process_handle, module_handle, IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress));
		HighLowWord *procedure_highlow = reinterpret_cast<HighLowWord *>(&procedure_name);
		if (procedure_highlow->high_word)
		{
			std::vector<DWORD> name_offsets(export_directory.NumberOfNames);
			pfw::GetRemoteMemory(process_handle, reinterpret_cast<char *>(module_handle) + export_directory.AddressOfNames, name_offsets.data(), sizeof(DWORD) * export_directory.NumberOfNames);
			for (std::size_t i = 0; i < name_offsets.size(); i++)
			{
				std::string procedure_entry_name = pfw::stringutils::GetRemoteString(process_handle, reinterpret_cast<char *>(module_handle) + name_offsets[i]);
				if (procedure_entry_name.compare(procedure_name) == 0)
				{
					WORD ordinal = pfw::GetRemoteMemory(process_handle, reinterpret_cast<WORD *>(reinterpret_cast<char *>(module_handle) + export_directory.AddressOfNameOrdinals) + i);
					return reinterpret_cast<char *>(module_handle) + pfw::GetRemoteMemory(process_handle, reinterpret_cast<DWORD *>(reinterpret_cast<char *>(module_handle) + export_directory.AddressOfFunctions) + ordinal);
				}
			}
		}
		else
		{
			return reinterpret_cast<char *>(module_handle) + pfw::GetRemoteMemory(process_handle, reinterpret_cast<DWORD *>(reinterpret_cast<char *>(module_handle) + export_directory.AddressOfFunctions) + procedure_highlow->ordinal);
		}
		throw std::runtime_error("derive this error");
	}

	template <typename Type>
	Type GetRemoteProcAddress(HANDLE process_handle, HMODULE module_handle, const char *procedure_name)
	{
		return reinterpret_cast<Type>(pfw::GetRemoteProcAddress(process_handle, module_handle, procedure_name));
	}

	std::size_t GetRemoteMemory(HANDLE process_handle, const void *source, void *destination, std::size_t size)
	{
		SIZE_T size_read;
		if (!ReadProcessMemory(process_handle, source, destination, size, &size_read))
			throw std::runtime_error("derive this error");
		else if (size_read != size)
			throw std::runtime_error("derive this error");
		return std::size_t(size_read);
	}

	template <typename TypePointer,
			  typename = std::enable_if_t<std::is_pointer_v<TypePointer> &&
										  !std::is_void_v<std::remove_pointer_t<TypePointer>>>>
	auto GetRemoteMemory(HANDLE process_handle, const TypePointer source)
	{
		using Type = typename std::remove_const_t<std::remove_pointer_t<TypePointer>>;
		Type memory;
		pfw::GetRemoteMemory(process_handle, source, &memory, sizeof(Type));
		return memory;
	}

	template <typename Type>
	Type GetRemoteMemory(HANDLE process_handle, const void *source)
	{
		return GetRemoteMemory(process_handle, const_cast<std::add_const_t<std::add_pointer_t<Type>>>(static_cast<std::add_pointer_t<Type>>(const_cast<void *>(source))));
	}

	std::size_t SetRemoteMemory(HANDLE process_handle, void *address, const void *buffer, std::size_t size)
	{
		SIZE_T size_written = 0;
		if (!WriteProcessMemory(process_handle, destination, source, size, &size_written))
			throw std::runtime_error("derive this error");
		else if (size_written != size)
			throw std::runtime_error("derive this error");
		return std::size_t(size_written);
	}

	template <typename Type, typename = std::enable_if_t<std::is_same<Type, std::decay_t<Type>>::value>>
	std::size_t SetRemoteMemory(HANDLE process_handle, void *address, const Type &value)
	{
		SIZE_T size_written = 0;
		pfw::SetRemoteMemory(process_handle, address, &value, sizeof(Type));
		return std::size_t(size_written);
	}

	template <typename TypePointer, typename = std::enable_if_t<std::is_pointer_v<TypePointer>>>
	class RemoteReference
	{
		using Type = std::remove_pointer_t<TypePointer>;

	public:
		Type recent_value_ = {};

		RemoteReference(HANDLE process_handle, TypePointer address) : process_handle_(process_handle), address_(address)
		{
			this->GetRemoteMemory();
		}

		operator Type()
		{
			return this->GetRemoteMemory();
		}

		TypePointer &operator&()
		{
			return this->address_;
		}

		RemoteReference<TypePointer> operator[](std::size_t index)
		{
			if (index == 0)
				return *this;
			RemoteReference<TypePointer> array_entry(this->process_handle_, this->address_ + index);
			return array_entry;
		}

		RemoteReference<TypePointer> &operator=(const Type &value)
		{
			Type temp = this->recent_value_;
			this->recent_value_ = value;
			if (!this->SetRemoteMemory())
			{
				this->recent_value_ = temp;
			}
			return *this;
		};

		RemoteReference<TypePointer> &operator=(Type &&value)
		{
			Type temp = this->recent_value_;
			this->recent_value_ = value;
			if (!this->SetRemoteMemory())
			{
				this->recent_value_ = temp;
			}
			return *this;
		};

		template <typename TypePointer_ = Type>
		RemoteReference<TypePointer_> &operator*()
		{
			this->GetRemoteMemory();
			RemoteReference<TypePointer_> dereferenced(this->process_handle_, this->recent_value_);
			return dereferenced;
		}

		Type GetRemoteMemory()
		{
			this->recent_value_ = pfw::GetRemoteMemory(this->process_handle_, this->address_);
			return this->recent_value_;
		}

		std::size_t SetRemoteMemory()
		{
			SIZE_T size_written = 0;
			size_written = pfw::SetRemoteMemory(this->process_handle_, this->address_, this->recent_value_);
			return std::size_t(size_written);
		}

	private:
		HANDLE process_handle_ = nullptr;
		TypePointer address_ = nullptr;
	};

	/*template <typename Type>
	std::istream& operator>>(std::istream& is, const RemoteReference<Type>& remote_reference)
	{
		// read obj from stream
		if ( /* T could not be constructed */
	/*)
is.setstate(std::ios::failbit);
return is;
}*/

	template <typename TypePointer, typename = std::enable_if_t<std::is_pointer_v<TypePointer>>>
	class RemotePointer
	{
		using Type = typename std::remove_pointer<TypePointer>::type;

	public:
		Type recent_value_ = {};
		TypePointer address_ = nullptr;

		RemotePointer(HANDLE process_handle, TypePointer address, bool static_memory = true) : process_handle_(process_handle), address_(address), static_memory_(static_memory)
		{
			this->GetRemoteMemory();
		}

		RemotePointer<TypePointer> &operator=(const TypePointer &address)
		{
			this->address_ = address;
			GetRemoteMemory();
			return *this;
		}

		RemotePointer<TypePointer> &operator=(TypePointer &&address)
		{
			this->address_ = address;
			GetRemoteMemory();
			return *this;
		}

		RemotePointer<TypePointer> &operator=(const void *&address)
		{
			this->address_ = address;
			GetRemoteMemory();
			return *this;
		}

		RemotePointer<TypePointer> &operator=(void *&&address)
		{
			this->address_ = address;
			GetRemoteMemory();
			return *this;
		}

		operator TypePointer()
		{
			return reinterpret_cast<TypePointer>(this->address_);
		}

		operator Type()
		{
			GetRemoteMemory();
			return this->recent_value_;
		}

		auto operator*()
		{
			this->GetRemoteMemory();
			RemoteReference<Type> dereferenced(this->process_handle_, this->address_);
			return dereferenced;
		}

		auto operator->()
		{
			if (!this->static_memory_)
				this->GetRemoteMemory();
			return &this->recent_value_;
		}

		Type GetRemoteMemory()
		{
			this->recent_value_ = pfw::GetRemoteMemory<Type>(this->process_handle_, this->address_);
			return this->recent_value_;
		}

		std::size_t SetRemoteMemory()
		{
			SIZE_T size_written = 0;
			size_written = pfw::SetRemoteMemory(this->process_handle_, this->address_, this->recent_value_);
			return std::size_t(size_written);
		}

	private:
		HANDLE process_handle_ = nullptr;
		bool static_memory_ = true;
	};

	bool CheckMemorySignature(void *address, const char *signature, const char *mask)
	{
		size_t signatureLength = strlen(signature);
		for (size_t i = 0; i < signatureLength; i++)
		{
			if (mask[i] == 'x' && static_cast<char *>(address)[i] != signature[i])
			{
				return false;
			}
		}
		return true;
	}

	void *ScanSignature(const pfw::Module &module, const char *signature, const char *mask)
	{
		void *moduleMemory = VirtualAlloc(nullptr, module.base_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!GetRemoteMemory(module.process_handle, module.base, moduleMemory, module.base_size))
		{
			return nullptr;
		}
		for (DWORD offset = NULL; offset < module.base_size; offset++)
		{
			if (pfw::CheckMemorySignature(static_cast<char *>(moduleMemory) + offset, signature, mask))
			{
				VirtualFree(moduleMemory, NULL, MEM_RELEASE);
				return static_cast<char *>(module.base) + offset;
			}
		}
		VirtualFree(moduleMemory, NULL, MEM_RELEASE);
		return nullptr;
	}

	void *ScanSignatureEx(const pfw::Module &module, const char *signature, const char *mask, uintptr_t signature_offset, uintptr_t address_offset, bool read)
	{
		void *address = static_cast<char *>(pfw::ScanSignature(module, signature, mask)) + signature_offset;
		if (address == nullptr)
		{
			return nullptr;
		}
		if (read)
		{
			address = pfw::GetRemoteMemory<void *>(module.process_handle, address);
		}
		return static_cast<char *>(address) + address_offset;
	}

#endif // __PFWLIB_H__