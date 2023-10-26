#pragma once

#include <Windows.h>
#include <Psapi.h>

class SigScan
{
public:
	// For getting information about the executing module
	MODULEINFO GetModuleInfo(char *szModule)
	{
		MODULEINFO modinfo = { 0 };
		HMODULE hModule = GetModuleHandle(szModule);
		if (hModule == 0)
			return modinfo;
		GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
		return modinfo;
	}

	// for finding a signature/pattern in memory of another process
	DWORD FindPattern(const char *module, const char *pattern, const char *mask)
	{
		MODULEINFO mInfo = GetModuleInfo((char*)module);
		DWORD base = (DWORD)mInfo.lpBaseOfDll;
		DWORD size = (DWORD)mInfo.SizeOfImage; 

		if (!strcmp(module, "server.dll"))
		{ 
			base = 0x22000000; 
			size = 0x641fff;
		}

		DWORD patternLength = (DWORD)strlen(mask);

		for (DWORD i = 0; i < size - patternLength; i++)
		{
			bool found = true;
			for (DWORD j = 0; j < patternLength; j++)
			{
				found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
			}
			if (found)
			{
				return base + i;
			}
		}

		return NULL;
	}
};
