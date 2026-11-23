#include <Windows.h>
#include <stdio.h>
#include <stddef.h> 

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

	LONGLONG optionalHeaderOffset =
		fileHeaderOffset + (LONGLONG)sizeof(fileHeader);

	if (fileHeader.SizeOfOptionalHeader < sizeof(WORD) ||
		(LONGLONG)fileHeader.SizeOfOptionalHeader >
		liFileSize.QuadPart - optionalHeaderOffset)
	{
		fprintf(stderr, "[-] Invalid optional header size\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	WORD optionalMagic = 0;
	if (!ReadFile(hFile, &optionalMagic, sizeof(optionalMagic),
		&dwBytesRead, NULL))
	{
		fprintf(stderr, "[-] ReadFile(optional magic) - E%lu\n",
			GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (dwBytesRead != sizeof(optionalMagic))
	{
		fprintf(stderr, "[-] Incomplete optional header magic\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		printf("[+] Format: PE32\n");
	}
	else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		printf("[+] Format: PE32+\n");
	}
	else
	{
		fprintf(stderr, "[-] Unsupported optional header magic - [%04x]\n",
			(unsigned int)optionalMagic);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	size_t fixedOptionalSize =
		optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
		? offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory)
		: offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);

	if ((size_t)fileHeader.SizeOfOptionalHeader < fixedOptionalSize)
	{
		fprintf(stderr, "[-] Truncated fixed optional header\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	size_t directoryCountOffset =
		optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
		? offsetof(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes)
		: offsetof(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes);

	LARGE_INTEGER directoryCountPosition = { 0 };
	directoryCountPosition.QuadPart =
		optionalHeaderOffset + (LONGLONG)directoryCountOffset;

	if (!SetFilePointerEx(hFile, directoryCountPosition, NULL, FILE_BEGIN))
	{
		fprintf(stderr, "[-] SetFilePointerEx(directory count) - E%lu\n",
			GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	DWORD directoryCount = 0;
	if (!ReadFile(hFile, &directoryCount, sizeof(directoryCount),
		&dwBytesRead, NULL))
	{
		fprintf(stderr, "[-] ReadFile(directory count) - E%lu\n",
			GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (dwBytesRead != sizeof(directoryCount))
	{
		fprintf(stderr, "[-] Incomplete directory count\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	size_t directoryCapacity =
		((size_t)fileHeader.SizeOfOptionalHeader - fixedOptionalSize) /
		sizeof(IMAGE_DATA_DIRECTORY);

	if ((size_t)directoryCount > directoryCapacity)
	{
		fprintf(stderr, "[-] Data directories exceed optional header\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	printf("[+] Data-directory count: %lu\n", directoryCount);

	size_t entryPointOffset =
		optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
		? offsetof(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint)
		: offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint);

	DWORD entryPointRva = 0;

	if ((size_t)fileHeader.SizeOfOptionalHeader <
		entryPointOffset + sizeof(entryPointRva))
	{
		fprintf(stderr, "[-] Optional header lacks entry-point field\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	LARGE_INTEGER entryPointPosition = { 0 };
	entryPointPosition.QuadPart =
		optionalHeaderOffset + (LONGLONG)entryPointOffset;

	if (!SetFilePointerEx(hFile, entryPointPosition, NULL, FILE_BEGIN))
	{
		fprintf(stderr, "[-] SetFilePointerEx(entry point) - E%lu\n",
			GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (!ReadFile(hFile, &entryPointRva, sizeof(entryPointRva),
		&dwBytesRead, NULL))
	{
		fprintf(stderr, "[-] ReadFile(entry point) - E%lu\n",
			GetLastError());
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (dwBytesRead != sizeof(entryPointRva))
	{
		fprintf(stderr, "[-] Incomplete entry-point field\n");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	printf("[+] Entry-point RVA: 0x%08lx\n", entryPointRva);

	CloseHandle(hFile);

	return EXIT_SUCCESS;
}