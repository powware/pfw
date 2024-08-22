#pragma once

#include <cstdlib>

namespace pfw::hooking
{
	class TrampolineHook
	{
	public:
		TrampolineHook(void* splice, void* function_hook, std::size_t splice_size, bool push_entry_point);
		~TrampolineHook();
		void* GetTrampoline();
	private:
		void* splice_;
		void* function_hook_;
		void* trampoline_;
		std::size_t splice_size_;
		std::size_t trampoline_size_;
	};

	class VTableHook
	{
	public:
		VTableHook(void* class_pointer, std::size_t table_offset, std::size_t table_size);
		~VTableHook();
		void* AttachHook(void* function_hook, std::size_t table_entry_index);
		void DetachHook(std::size_t table_entry_index);

	private:
		void** hook_table_;
		void*** table_pointer_ = nullptr;
		void** source_table_;
		std::size_t table_size_;
		std::size_t table_entry_count_;
	};
}