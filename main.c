#include <Windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t* argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Invalid number of arguments - Expected 1, got %d\n", argc - 1);
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

	LARGE_INTEGER liFileSize = { 0 };
	if (!GetFileSizeEx(hFile, &liFileSize))
	{
		fprintf(stderr, "[-] GetFileSizeEx() - E%lu\n", GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}
	printf("[+] File size: %lld bytes\n", liFileSize.QuadPart);

	if (liFileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
	{
		fprintf(stderr, "[-] Invalid file size\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	IMAGE_DOS_HEADER iDosHeader = { 0 };
	DWORD dwBytesRead = 0;
	if (!ReadFile(
		hFile,
		&iDosHeader,
		sizeof(IMAGE_DOS_HEADER),
		&dwBytesRead,
		NULL
	)) {
		fprintf(stderr, "[-] ReadFile() - E%lu\n", GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (sizeof(IMAGE_DOS_HEADER) != dwBytesRead)
	{
		fprintf(stderr, "[-] Invalid number of bytes read - [%lu]\n", dwBytesRead);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (IMAGE_DOS_SIGNATURE != iDosHeader.e_magic)
	{
		fprintf(stderr, "[-] Invalid DOS signature - [%04x]\n", iDosHeader.e_magic);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (iDosHeader.e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
		(LONGLONG)iDosHeader.e_lfanew >
		liFileSize.QuadPart - (LONGLONG)sizeof(DWORD))
	{
		fprintf(stderr, "[-] Invalid PE header offset\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	LARGE_INTEGER peOffset = { 0 };
	peOffset.QuadPart = iDosHeader.e_lfanew;

	if (!SetFilePointerEx(hFile, peOffset, NULL, FILE_BEGIN))
	{
		fprintf(stderr, "[-] SetFilePointerEx() - E%lu\n", GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	DWORD peSignature = 0;
	if (!ReadFile(hFile, &peSignature, sizeof(peSignature),
		&dwBytesRead, NULL))
	{
		fprintf(stderr, "[-] ReadFile(PE signature) - E%lu\n", GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (dwBytesRead != sizeof(peSignature))
	{
		fprintf(stderr, "[-] Incomplete PE signature\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (peSignature != IMAGE_NT_SIGNATURE)
	{
		fprintf(stderr, "[-] Invalid PE signature - [%08lx]\n", peSignature);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	printf("[+] DOS and PE signatures verified\n");

	LONGLONG fileHeaderOffset =
		peOffset.QuadPart + (LONGLONG)sizeof(peSignature);

	if (liFileSize.QuadPart - fileHeaderOffset <
		(LONGLONG)sizeof(IMAGE_FILE_HEADER))
	{
		fprintf(stderr, "[-] Truncated PE file header\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	IMAGE_FILE_HEADER fileHeader = { 0 };
	if (!ReadFile(hFile, &fileHeader, sizeof(fileHeader),
		&dwBytesRead, NULL))
	{
		fprintf(stderr, "[-] ReadFile(file header) - E%lu\n", GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (dwBytesRead != sizeof(fileHeader))
	{
		fprintf(stderr, "[-] Incomplete PE file header\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	printf("[+] Machine: 0x%04x\n", (unsigned int)fileHeader.Machine);
	printf("[+] Characteristics: 0x%04x\n",
		(unsigned int)fileHeader.Characteristics);
	printf("[+] DLL flag: %s\n",
		(fileHeader.Characteristics & IMAGE_FILE_DLL) ? "set" : "clear");

	CloseHandle(hFile);

	return EXIT_SUCCESS;
}