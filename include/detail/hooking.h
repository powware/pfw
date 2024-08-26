#ifndef __HOOKING_H__
#define __HOOKING_H__

#include <array>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <vector>

#include <Windows.h>

// __thiscall should be hooked with __fastcall and the second argument left unused

namespace pfw
{
	class ProtectGuard
	{
	public:
		ProtectGuard(void *address, std::size_t size) : address_(address), size_(size)
		{
			DWORD new_protection = PAGE_EXECUTE_READWRITE;
			VirtualProtect(address_, size_, new_protection, &original_protection_);
		}

		ProtectGuard(std::uintptr_t address, std::size_t size) : ProtectGuard(reinterpret_cast<void *>(address), size) {}

		~ProtectGuard()
		{
			VirtualProtect(address_, size_, original_protection_, nullptr);
		}

	private:
		void *address_;
		std::size_t size_;
		DWORD original_protection_;
	};

	class Nop
	{
	public:
		Nop(void *address, std::size_t size) : address_(address), original_opcode_()
		{
			original_opcode_.resize(size);

			ProtectGuard protect_guard(address_, original_opcode_.size());

			std::memcpy(original_opcode_.data(), address_, original_opcode_.size());
			std::memset(address_, 0x90, original_opcode_.size());
		}

		Nop(std::uintptr_t address, std::size_t size) : Nop(reinterpret_cast<void *>(address), size) {}

		~Nop()
		{
			ProtectGuard protect_guard(address_, original_opcode_.size());

			std::memcpy(address_, original_opcode_.data(), original_opcode_.size());
		}

	private:
		void *address_;
		std::vector<unsigned char> original_opcode_;
	};

	class InlineHook
	{
	public:
		InlineHook(void *address, void *hook) : address_(address)
		{
			const std::array<unsigned char, 5> jmp_opcode({0xE9, 0x0, 0x0, 0x0, 0x0}); // jmp near relative

			ProtectGuard protect_guard(address, jmp_opcode.size());

			std::memcpy(original_opcode_.data(), address_, original_opcode_.size());
			std::memcpy(address_, jmp_opcode.data(), jmp_opcode.size());
			const auto offset = reinterpret_cast<std::intptr_t>(hook) - (reinterpret_cast<std::intptr_t>(address) + jmp_opcode.size());
			std::memcpy(static_cast<unsigned char *>(address_) + 1, &offset, sizeof(offset));
		}
		InlineHook(std::uintptr_t address, void *hook) : InlineHook(reinterpret_cast<void *>(address), hook) {}
		~InlineHook()
		{
			ProtectGuard protect_guard(address_, original_opcode_.size());

			std::memcpy(reinterpret_cast<void *>(address_), original_opcode_.data(), original_opcode_.size());
		}

	private:
		void *address_;
		std::array<unsigned char, 5> original_opcode_;
	};

	class VTableFunctionOverride
	{
	public:
		VTableFunctionOverride(void *address, void *hook) : address_(address)
		{
			ProtectGuard protect_guard(address, sizeof(void *));

			std::memcpy(&original_, address_, sizeof(void *));
			std::memcpy(address_, &hook, sizeof(void *));
		}
		VTableFunctionOverride(std::uintptr_t address, void *hook) : VTableFunctionOverride(reinterpret_cast<void *>(address), hook) {}
		~VTableFunctionOverride()
		{
			ProtectGuard protect_guard(address_, sizeof(void *));

			std::memcpy(address_, &original_, sizeof(void *));
		}

	private:
		void *address_;
		void *original_;
	};

	class TrampolineHook
	{
	public:
		TrampolineHook(void *splice, void *function_hook, std::size_t splice_size, bool push_entry_point) : splice_(splice), function_hook_(function_hook), splice_size_(splice_size)
		{
			DWORD old_protection;
			DWORD new_protection = PAGE_EXECUTE_READWRITE;

			unsigned char jump_near_relative32[] = {0xE9, 0x0, 0x0, 0x0, 0x0};
			unsigned char push_immediate32[] = {0x58, 0x68, 0x0, 0x0, 0x0, 0x0, 0x50};
			trampoline_size_ = splice_size_ + sizeof(jump_near_relative32);
			trampoline_ = VirtualAlloc(nullptr, trampoline_size_, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			intptr_t jump_to_splice_end = (static_cast<char *>(splice_) + splice_size_) - (static_cast<char *>(trampoline_) + splice_size_ + sizeof(jump_near_relative32));
			*reinterpret_cast<intptr_t *>(&jump_near_relative32[1]) = jump_to_splice_end;
			std::memcpy(static_cast<char *>(trampoline_) + splice_size_, jump_near_relative32, sizeof(jump_near_relative32));

			intptr_t jump_to_function_hook = static_cast<char *>(function_hook_) - (static_cast<char *>(splice_) + push_entry_point * sizeof(push_immediate32) + sizeof(jump_near_relative32));
			*reinterpret_cast<intptr_t *>(&jump_near_relative32[1]) = jump_to_function_hook;

			VirtualProtect(splice_, splice_size_, new_protection, &old_protection);
			std::memcpy(trampoline_, splice_, splice_size_);
			if (push_entry_point)
			{
				*reinterpret_cast<void **>(&push_immediate32[2]) = trampoline_;
				std::memcpy(splice_, push_immediate32, sizeof(push_immediate32));
			}
			std::memcpy(static_cast<char *>(splice_) + push_entry_point * sizeof(push_immediate32), jump_near_relative32, sizeof(jump_near_relative32));
			VirtualProtect(splice_, splice_size_, old_protection, NULL);
		};
		~TrampolineHook()
		{
			std::memcpy(splice_, trampoline_, splice_size_);
			VirtualFree(trampoline_, 0, MEM_RELEASE);
		}
		void *GetTrampoline()
		{
			return trampoline_;
		}

	private:
		void *splice_;
		void *function_hook_;
		void *trampoline_;
		std::size_t splice_size_;
		std::size_t trampoline_size_;
	};

	class VTableHook
	{
	public:
		VTableHook(void *instance, std::size_t function_count, std::size_t table_offset = 0) : vtable_pointer_(reinterpret_cast<void ***>(static_cast<char *>(instance) + table_offset)), vtable_(function_count + 2)
		{
			original_vtable_ = std::span<void *>(*reinterpret_cast<void ***>(static_cast<char *>(instance) + table_offset - 2), function_count);
			std::memcpy(vtable_.data(), original_vtable_.data(), function_count * sizeof(void *));
			*vtable_pointer_ = &vtable_[2];
		}
		~VTableHook()
		{
			*vtable_pointer_ = original_vtable_.data();
		}

		auto &operator[](std::size_t index)
		{
			return vtable_[index];
		}

	private:
		void ***vtable_pointer_;
		std::vector<void *> vtable_;

	public:
		std::span<void *> original_vtable_;
		// void **original_vtable_;
	};
}
#endif // __HOOKING_H__