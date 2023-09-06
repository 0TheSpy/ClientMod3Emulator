// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream> 
 
#include "XorStr.h"
 
#pragma comment(lib, "detours.lib")
#include "detours.h" 
#include "sigscan.h"
 
using namespace std;
 
DWORD e4331B;

DWORD _esi_;

__declspec(naked) void dummy()
{ 
	__asm
	{
		mov ecx, 0x82
		pushad 
	}

	__asm mov [_esi_], esi

	printf("NET_SetConVar %s : %s\n", (char*)_esi_, (char*)(_esi_ + 0x104) );
	 
	__asm 
	{
		popad
		jmp [e4331B]
	}
}


DWORD WINAPI HackThread(HMODULE hModule)
{  
	AllocConsole(); FILE* f; freopen_s(&f, "CONOUT$", "w", stdout);

	Beep(400, 300); 

	printf(XorStr("SpyAddon: console allocated\n"));
	    
	printf("Dummy %x\n", dummy);
	 
	DWORD dwEngine = (DWORD)GetModuleHandleA("engine.dll");
	e4331B = dwEngine + 0x4331B;

	//74 0B 8B 74 24 14 B9 82 00 00 00 F3 A5 5F
	// + 6 - jmp // + 11 - back
	SigScan scan;
	e4331B = scan.FindPattern(XorStr("engine.dll"), XorStr("\x74\x0B\x8B\x74\x24\x14\xB9\x82\x00\x00\x00\xF3\xA5\x5F"), XorStr("xxxxxxxxxxxxxx")); //engine.dll+0x43316
	e4331B += 11;
	printf("e4331B %x\n", e4331B); 

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DWORD e43316 = e4331B - 5;
	DetourAttach(&(LPVOID&)e43316, &dummy);
	DetourTransactionCommit();

	while (true)
	{ 
		if (GetAsyncKeyState(VK_DELETE))  break;
		Sleep(100);
	} 

	Beep(400, 300);
	printf("Unhooking...\n");
	 
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(LPVOID&)e43316, reinterpret_cast<BYTE*>(dummy));
	DetourTransactionCommit(); 
	  
	//if (f) fclose(f); FreeConsole();

	FreeLibraryAndExitThread(hModule, 0);
	
	return 0;
} 

BOOL APIENTRY DllMain( HMODULE hModule, 
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		HANDLE hdl = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, nullptr);
		if (hdl) CloseHandle(hdl);
		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

