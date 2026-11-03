#include <Windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t* argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "%ls needs 1 argument\n", argv[0]);
		return EXIT_FAILURE;
	}

	HANDLE hFile = CreateFileW(
		argv[1],
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		fprintf(stderr, "[-] CreateFileW() - E%lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}