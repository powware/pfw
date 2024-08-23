#include "hooking.h"

#include <cstring>

#include <Windows.h>

pfw::hooking::TrampolineHook::TrampolineHook(void *splice, void *function_hook, std::size_t splice_size, bool push_entry_point) : splice_(splice), function_hook_(function_hook), splice_size_(splice_size)
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

pfw::hooking::TrampolineHook::~TrampolineHook()
{
	std::memcpy(splice_, trampoline_, splice_size_);
	VirtualFree(trampoline_, 0, MEM_RELEASE);
}

void *pfw::hooking::TrampolineHook::GetTrampoline()
{
	return trampoline_;
}

pfw::hooking::VTableHook::VTableHook(void *class_pointer, std::size_t table_offset, std::size_t table_size)
	: table_pointer_(reinterpret_cast<void ***>(static_cast<char *>(class_pointer) + table_offset)),
	  source_table_(*table_pointer_),
	  table_size_(table_size),
	  table_entry_count_(table_size_ / sizeof(void *))
{
	hook_table_ = new void *[table_entry_count_];
	std::memcpy(hook_table_, source_table_, table_size_);
	*table_pointer_ = hook_table_;
}

pfw::hooking::VTableHook::~VTableHook()
{
	*table_pointer_ = source_table_;
	delete[] hook_table_;
}

void *pfw::hooking::VTableHook::AttachHook(void *function_hook, std::size_t table_entry_index)
{
	if (table_entry_index >= table_entry_count_)
		return nullptr;
	void *previous_entry = hook_table_[table_entry_index];
	hook_table_[table_entry_index] = function_hook;
	return previous_entry;
}

void pfw::hooking::VTableHook::DetachHook(std::size_t table_entry_index)
{
	hook_table_[table_entry_index] = source_table_[table_entry_index];
}
