#pragma once 

#include <cstdlib>
#include <memory>
#include <string>

#include "windows_extensions.h"

namespace pfw
{
	struct Module
	{
		HANDLE process_handle = INVALID_HANDLE_VALUE;
		void* base = nullptr;
		std::size_t base_size = NULL;

		DWORD_PTR operator+(DWORD offset)
		{
			return reinterpret_cast<DWORD_PTR>(static_cast<char*>(this->base) + offset);
		}
	};

	class VirtualMemory
	{
	public:
		VirtualMemory(void* target_address, std::size_t size, DWORD allocation_type, DWORD protection) : size_(size),
			handle_(std::shared_ptr<HANDLE>(static_cast<HANDLE*>(VirtualAlloc(target_address, size, allocation_type, protection)), [](HANDLE h)
				{
					VirtualFree(h, 0, MEM_RELEASE);
				}))
		{
			if (this->handle_ == nullptr)
				throw std::bad_alloc();
		}

		template<typename T>
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
		RemoteVirtualMemory(HANDLE process_handle, void* target_address, std::size_t size, DWORD allocation_type, DWORD protection) : process_handle_(process_handle), size_(size),
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

		template<typename T>
		operator T() const
		{
			return handle_;
		}

	private:
		HANDLE process_handle_;
		std::size_t size_;
		HANDLE handle_;
	};

	std::string GetLastErrorString();

	void SetDebugPrivileges();

	DWORD GetProcessId(std::string_view process_name);

	HANDLE GetProcessHandle(DWORD process_id);

	HANDLE GetProcessHandle(std::string_view process_name);

	class ProcessHandle
	{
	public:
		ProcessHandle(DWORD process_id) : handle_(pfw::GetProcessHandle(process_id)) {}

		~ProcessHandle()
		{
			CloseHandle(this->handle_);
		}

		template<typename T>
		operator T()
		{
			return this->handle_;
		}

	private:
		HANDLE handle_;
	};

	pfw::PEB GetRemotePEB(HANDLE process_handle);

	HMODULE GetRemoteModuleHandle(HANDLE process_handle, std::string_view module_name);

	void* GetRemoteProcAddress(HANDLE process_handle, HMODULE module_handle, const char* procedure_name);

	template <typename Type>
	Type GetRemoteProcAddress(HANDLE process_handle, HMODULE module_handle, const char* procedure_name)
	{
		return reinterpret_cast<Type>(pfw::GetRemoteProcAddress(process_handle, module_handle, procedure_name));
	}

	std::size_t GetRemoteMemory(HANDLE process_handle, const void* source, void* destination, std::size_t size);

	template<typename TypePointer,
		typename = std::enable_if_t<std::is_pointer_v<TypePointer> &&
		!std::is_void_v<std::remove_pointer_t<TypePointer>>>>
	auto GetRemoteMemory(HANDLE process_handle, const TypePointer source)
	{
		using Type = typename std::remove_const_t<std::remove_pointer_t<TypePointer>>;
		Type memory;
		pfw::GetRemoteMemory(process_handle, source, &memory, sizeof(Type));
		return memory;
	}

	template<typename Type>
	Type GetRemoteMemory(HANDLE process_handle, const void* source)
	{
		return GetRemoteMemory( process_handle, const_cast<std::add_const_t<std::add_pointer_t<Type>>>(static_cast<std::add_pointer_t<Type>>(const_cast<void*>(source))));
	}

	std::size_t SetRemoteMemory(HANDLE process_handle, void* address, const void* buffer, std::size_t size);

	template <typename Type, typename = std::enable_if_t<std::is_same<Type, std::decay_t<Type>>::value>>
	std::size_t SetRemoteMemory(HANDLE process_handle, void* address, const Type& value)
	{
		SIZE_T size_written = 0;
		pfw::SetRemoteMemory(process_handle, address, &value, sizeof(Type));
		return std::size_t(size_written);
	}

	template<typename TypePointer, typename = std::enable_if_t<std::is_pointer_v<TypePointer>>>
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

		TypePointer& operator&()
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

		RemoteReference<TypePointer>& operator=(const Type& value)
		{
			Type temp = this->recent_value_;
			this->recent_value_ = value;
			if (!this->SetRemoteMemory())
			{
				this->recent_value_ = temp;
			}
			return *this;
		};

		RemoteReference<TypePointer>& operator=(Type&& value)
		{
			Type temp = this->recent_value_;
			this->recent_value_ = value;
			if (!this->SetRemoteMemory())
			{
				this->recent_value_ = temp;
			}
			return *this;
		};

		template<typename TypePointer_ = Type>
		RemoteReference<TypePointer_>& operator *()
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
		if ( /* T could not be constructed *//*)
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

		RemotePointer<TypePointer>& operator =(const TypePointer& address)
		{
			this->address_ = address;
			GetRemoteMemory();
			return *this;
		}
		
		RemotePointer<TypePointer>& operator =(TypePointer&& address)
		{
			this->address_ = address;
			GetRemoteMemory();
			return *this;
		}

		RemotePointer<TypePointer>& operator =(const void*& address)
		{
			this->address_ = address;
			GetRemoteMemory();
			return *this;
		}

		RemotePointer<TypePointer>& operator =(void*&& address)
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

		auto operator *()
		{
			this->GetRemoteMemory();
			RemoteReference<Type> dereferenced(this->process_handle_, this->address_);
			return dereferenced;
		}

		auto operator ->()
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

	bool CheckMemorySignature(void* address, const char* signature, const char* mask);

	void* ScanSignature(const pfw::Module& module, const char* signature, const char* mask);

	void* ScanSignatureEx(const pfw::Module& module, const char* signature, const char* mask, uintptr_t signatureOffset, uintptr_t addressOffset, bool read);

	class RemoteThread
	{
	public:
		RemoteThread(HANDLE process_handle, void* start_routine, void* parameters) : handle_(CreateRemoteThread(process_handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(start_routine), parameters, 0, nullptr))
		{
			if (this->handle_ == nullptr)
				throw "";
		}

		~RemoteThread()
		{
			CloseHandle(this->handle_);
		}

		bool Join(DWORD milliseconds = INFINITE)
		{
			DWORD result = WaitForSingleObject(this->handle_, milliseconds);
			if (result == WAIT_OBJECT_0)
			{
				return true;
			}
			return false;
		}

		DWORD GetExitCode()
		{
			DWORD exit_code;
			GetExitCodeThread(this->handle_, &exit_code);
			return exit_code;
		}

		template<typename T>
		operator T()
		{
			return this->handle_;
		}

	private:
		HANDLE handle_;
	};
}

#include "hooking.h"
#include "stringutils.h"
#include "pefile.h"
