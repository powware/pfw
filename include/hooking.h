#pragma once

#include <array>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include <Windows.h>

// __thiscall should be hooked with __fastcall and the second argument left unused

namespace pfw::hooking
{
	class ProtectGuard
	{
	public:
		ProtectGuard(void *address, std::size_t size);
		ProtectGuard(std::uintptr_t address, std::size_t size) : ProtectGuard(reinterpret_cast<void *>(address), size) {}
		~ProtectGuard();

	private:
		void *address_;
		std::size_t size_;
		DWORD original_protection_;
	};

	class Nop
	{
	public:
		Nop(void *address, std::size_t size);
		Nop(std::uintptr_t address, std::size_t size) : Nop(reinterpret_cast<void *>(address), size) {}
		~Nop();

	private:
		void *address_;
		std::vector<unsigned char> original_opcode_;
	};

	class InlineHook
	{
	public:
		InlineHook(void *address, void *hook);
		InlineHook(std::uintptr_t address, void *hook) : InlineHook(reinterpret_cast<void *>(address), hook) {}
		~InlineHook();

	private:
		void *address_;
		std::array<unsigned char, 5> original_opcode_;
	};

	class VTableFunctionOverride
	{
	public:
		VTableFunctionOverride(void *address, void *hook);
		VTableFunctionOverride(std::uintptr_t address, void *hook) : VTableFunctionOverride(reinterpret_cast<void *>(address), hook) {}
		~VTableFunctionOverride();

	private:
		void *address_;
		void *original_;
	};

	class TrampolineHook
	{
	public:
		TrampolineHook(void *splice, void *function_hook, std::size_t splice_size, bool push_entry_point);
		~TrampolineHook();
		void *GetTrampoline();

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
		VTableHook(void *class_pointer, std::size_t table_offset, std::size_t table_size);
		~VTableHook();
		void *AttachHook(void *function_hook, std::size_t table_entry_index);
		void DetachHook(std::size_t table_entry_index);

	private:
		void **hook_table_;
		void ***table_pointer_ = nullptr;
		void **source_table_;
		std::size_t table_size_;
		std::size_t table_entry_count_;
	};
}