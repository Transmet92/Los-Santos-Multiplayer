/*
	Author: Transmet
	Project: Launcher
	Solution: Los Santos Multiplayer

	This is the source code of the LSMP Launcher (DLL injections
	specific for the needs of Los Santos Multiplayer projects).
*/

#define _CRT_SECURE_NO_WARNINGS
#include <SkyCommons/SkyCommons.h>

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <vector>

#ifdef _WIN32
#define APIENTRY __stdcall
#endif

#include <fstream>
#include <dbghelp.h>
#include <winternl.h>
#include <shlobj_core.h>

// #pragma comment(lib, "glfw3.lib")




/*
	THE FOLLOWING OPERATIONS SEEMS TRIGGER ALERT OF SOME ANTIVIRUS
	(look at the special includes)
*/
#pragma region(TO_FIX)
LONG GetStringRegKey(HKEY hKey, const std::wstring &strValueName, std::wstring &strValue)
{
	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (ERROR_SUCCESS == nError)
		strValue = szBuffer;

	return nError;
}

LONG SetStringRegKey(HKEY hKey, const std::wstring& strValueName, const wchar_t* strValue)
{
	ULONG nError;
	nError = RegSetValueExW(hKey, strValueName.c_str(), 0, NULL, (const BYTE*)strValue, lstrlenW(strValue));
	return nError;
}
#pragma endregion



int WINAPI WinMain(HINSTANCE hinstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	const wchar_t* dllsToInject[] = {
		// L"SandLayer_LSMP.dll",
		// L"Los Santos Multiplayer.dll",
		// L"CORE.dll",
		L"NoGTAVLauncher.dll"
	};





	/*
		RETRIEVE THE LSMP INFORMATIONS FROM THE GTA V REGISTRY
	*/
	HKEY hKey;
	LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Rockstar Games\\Grand Theft Auto V", 0, KEY_READ, &hKey);
	if (lRes != 0)
		MessageBoxA(0, "RegOpenKeyExW failed, please check the reg path 'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Rockstar Games\\Grand Theft Auto V', please re-install if the problem persist.", "LSMP Launcher", 0);


	// RETRIEVE GTA V InstallFolder KEY VALUE
	std::wstring InstallFolderOut;
	auto getKeyCode = GetStringRegKey(hKey, L"InstallFolder", InstallFolderOut);
	if (getKeyCode != 0)
		MessageBoxA(0, "RegQueryValueExW failed, please check the \"InstallFolder\" at 'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Rockstar Games\\Grand Theft Auto V', please re-install if the problem persist.", "LSMP Launcher", 0);


	// RETRIEVE LSMP KEY VALUE
	std::wstring FolderLSMP;
	auto getKeyCode0 = GetStringRegKey(hKey, L"LSMP", FolderLSMP);
	if (getKeyCode0 != 0)
		MessageBoxA(0, "RegQueryValueExW failed, please check the \"LSMP\" at 'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Rockstar Games\\Grand Theft Auto V', please re-install if the problem persist.", "LSMP Launcher", 0);




	std::wstring gta5exePath(InstallFolderOut);
	gta5exePath += L"\\GTA5.exe";



	// EXECUTE GTA V AND HOOK
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof si;

	SECURITY_ATTRIBUTES  sa = {};
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;

	if (CreateProcessW(gta5exePath.c_str(), 0, &sa, &sa, TRUE, CREATE_DEFAULT_ERROR_MODE, 0, InstallFolderOut.c_str(), &si, &pi))
	{
		SuspendThread(pi.hThread);

		for (uint16_t i = 0; i < sizeof(dllsToInject) / sizeof(dllsToInject[0]); i++)
		{
			std::wstring iPathLib(FolderLSMP);
			iPathLib += L"\\";
			iPathLib += dllsToInject[i];
			uint32 pathLengthBytes = lstrlenW(iPathLib.c_str()) * sizeof(wchar_t);

			// just retrieve the DoHook function address if exist
			auto hMod = LoadLibraryExW(iPathLib.c_str(), 0, DONT_RESOLVE_DLL_REFERENCES);
			auto hookFuncPtr = GetProcAddress(hMod, "DoHook");
			FreeLibrary(hMod);


			LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
			LPVOID dereercomp = VirtualAllocEx(pi.hProcess, NULL, pathLengthBytes + 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!dereercomp)
				MessageBoxA(0, "Failed allocate in process", "ERROR", 0);


			WriteProcessMemory(pi.hProcess, dereercomp, (char*)iPathLib.c_str(), pathLengthBytes, NULL);
			HANDLE loadLibThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
			if (loadLibThread == 0)
				MessageBoxA(0, "Failed allocate in process", "ERROR", 0);

			WaitForSingleObject(loadLibThread, INFINITE);
			DWORD exitThreadLoadLib = 0;
			if (GetExitCodeThread(loadLibThread, &exitThreadLoadLib))
			{
				if (exitThreadLoadLib == 0)
					MessageBoxW(0, L"Failed to inject DLL", dllsToInject[i], 0);

				// If DoHook EXIST
				if (hookFuncPtr)
				{
					HANDLE doHookThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)hookFuncPtr, 0, 0, NULL);
					if (doHookThread == 0)
						MessageBoxA(0, "Failed allocate DoHook thread in process", "ERROR", 0);

					WaitForSingleObject(doHookThread, INFINITE);
					CloseHandle(doHookThread);
				}
			}
			else
				MessageBoxA(0, "Failed to retrieve remote thread exit code", "ERROR", 0);

			VirtualFreeEx(pi.hProcess, dereercomp, pathLengthBytes, MEM_RELEASE);
			CloseHandle(loadLibThread);
		}

		ResumeThread(pi.hThread);
	}


	return 0;
}