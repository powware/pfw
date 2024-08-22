#include <iostream>

#include "windows.h"

int main()
{
	int integer = 12;
	int* integer_pointer = &integer;
	while (true)
	{
		std::cout << std::hex << &integer_pointer << " " << integer_pointer << " " << integer << std::endl;
		Sleep(1000);
	}
}