#include <stdio.h>
#include <windows.h>
#include <stdbool.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include "mouse.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Shlwapi.lib")

NTSTATUS HashDataWithSHA256(BYTE* input_data, ULONG input_size, BYTE* output_hash, ULONG output_size) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash_handle = NULL;
    DWORD hash_object_size = 0, result_length = 0;
    PUCHAR hash_object = NULL;
    NTSTATUS status;

    // Open an algorithm handle for SHA256
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0) {
        return status;
    }

    // Get the required size of the hash object
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_object_size, sizeof(DWORD), &result_length, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return status;
    }

    // Allocate the hash object
    hash_object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, hash_object_size);
    if (!hash_object) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return STATUS_NO_MEMORY;
    }

    // Create a hash handle
    status = BCryptCreateHash(algorithm, &hash_handle, hash_object, hash_object_size, NULL, 0, 0);
    if (status != 0) {
        HeapFree(GetProcessHeap(), 0, hash_object);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return status;
    }

    // Hash the data
    status = BCryptHashData(hash_handle, input_data, input_size, 0);
    if (status != 0) {
        BCryptDestroyHash(hash_handle);
        HeapFree(GetProcessHeap(), 0, hash_object);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return status;
    }

    // Get the final hash value
    status = BCryptFinishHash(hash_handle, output_hash, output_size, 0);

    // Cleanup
    BCryptDestroyHash(hash_handle);
    HeapFree(GetProcessHeap(), 0, hash_object);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    return status;
}

int GetWinBuildNumber() {
    RTL_OSVERSIONINFOW rovi = { 0 };
    rovi.dwOSVersionInfoSize = sizeof(rovi);

    NTSTATUS status = RtlGetVersion(&rovi);

    if (!NT_SUCCESS(status)) {
        wprintf(L"ERROR: RtlGetVersion failed: 0x%08X \n", status);
        return 0;
    }

    return rovi.dwBuildNumber;
}

BOOL GetRegistryStringValue(HKEY root_key, LPCWSTR sub_key, LPCWSTR value_name, wchar_t* buffer) {
    HKEY key_handle;
    LONG result;
    DWORD type = 0;
    DWORD data_size = 0;

    // Open the registry key
    result = RegOpenKeyExW(root_key, sub_key, 0, KEY_READ, &key_handle);
    if (result != ERROR_SUCCESS) {
        wprintf(L"ERROR: RegOpenKeyExW failed!\n");
        return false;
    }

    // Query the value to determine the required buffer size and type
    result = RegQueryValueExW(key_handle, value_name, NULL, &type, NULL, &data_size);
    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(key_handle);
        wprintf(L"ERROR: RegQueryValueExW failed!\n");
        return false;
    }

    // Read the actual string value
    result = RegQueryValueExW(key_handle, value_name, NULL, NULL, (LPBYTE)buffer, &data_size);
    RegCloseKey(key_handle);

    if (result != ERROR_SUCCESS) {
        wprintf(L"ERROR: RegQueryValueExW failed!\n");
        return false;
    }

    return true;
}

bool GetPCName(wchar_t* name) {
    return GetRegistryStringValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", L"ComputerName", name);
}

// Finds and returns the 30 second interval between two different SYSTEMTIME values
DWORD CalculateTickDelta(const SYSTEMTIME* current_st, const SYSTEMTIME* base_st) {
    FILETIME current_ft, base_ft;
    ULARGE_INTEGER current_t, base_t;

    // Convert SYSTEMTIME values to FILETIME format
    if (!SystemTimeToFileTime(current_st, &current_ft)) {
        wprintf(L"ERROR SystemTimeToFileTime failed!\n");
        return 0;
    }

    if (!SystemTimeToFileTime(base_st, &base_ft)) {
        wprintf(L"ERROR SystemTimeToFileTime failed!\n");
        return 0;
    }

    // Pack into 64-bit ints
    current_t.LowPart = current_ft.dwLowDateTime;
    current_t.HighPart = current_ft.dwHighDateTime;
    base_t.LowPart = base_ft.dwLowDateTime;
    base_t.HighPart = base_ft.dwHighDateTime;

    // Convert to seconds
    ULONGLONG now_secs = current_t.QuadPart / 10000000ULL;
    ULONGLONG base_secs = base_t.QuadPart / 10000000ULL;

    // Get the 30 second interval between the two SYSTEMTIME values
    ULONGLONG delta_secs = now_secs - base_secs;
    return (DWORD)(delta_secs / 30ULL);
}

DWORD GetTicks(SYSTEMTIME curr_st) {
    // This is the "base" time we reverse engineered
    SYSTEMTIME base_time = {
        .wYear = 2009,
        .wMonth = 4,
        .wDay = 22,
        .wHour = 19,
        .wMinute = 25,
        .wSecond = 0,
        .wMilliseconds = 0
    };

    DWORD ticks = CalculateTickDelta(&curr_st, &base_time);

    if (!ticks)
        return 0;

    return ticks;
}

DWORD CreateHash(int build_number, wchar_t* computer_name, int ticks, wchar_t* salt, wchar_t* hash) {
    swprintf(hash, 256, L"%d%ws%d%ws", build_number, computer_name, ticks, salt);

    BYTE HashOutput[32]; // SHA-256 outputs 32 bytes
    LONGLONG status;

    status = HashDataWithSHA256(
        (BYTE*)hash,
        (DWORD)(wcslen(hash) * sizeof(wchar_t)),
        HashOutput,
        sizeof(HashOutput)
    );

    if (!NT_SUCCESS(status)) {
        wprintf(L"ERROR: Hashing failed. NTSTATUS: 0x%llx \n", status);
        return 0;
    }

    // Print the hash output (debugging purposes)
    //for (int i = 0; i < sizeof(HashOutput); i++) {
    //    printf("%02x", HashOutput[i]);
    //}

    // Return first 4 bytes (DWORD)
    return *(DWORD*)HashOutput;
}

// Build the auth token
bool DriverAuth(HANDLE hDriver) {
    int build_number = GetWinBuildNumber();
    if (!build_number) {
        wprintf(L"ERROR: GetWinBuildNumber failed!\n");
        return false;
    }

    wchar_t pc_name[1024];
    if (!GetPCName(pc_name)) {
        wprintf(L"ERROR: GetPCName failed!\n");
        return false;
    }

    // We can't use the current time because the driver checks if the year is 2024. 
    // Any date after December 2024 won't work
    SYSTEMTIME st;
    st.wYear = 2024;
    st.wMonth = 10;
    st.wDay = 1;
    st.wHour = 1;
    st.wMinute = 0;
    st.wSecond = 0;
    st.wMilliseconds = 0;

    int ticks = GetTicks(st);
    if (!ticks) {
        wprintf(L"ERROR: SetAndGetTicks failed!\n");
    }

    // this is the "salt" used in the hash that we reverse engineered:
    wchar_t* salt = L"dREAMpIKAcHu";

    wchar_t hash[1024];

    DWORD token = CreateHash(build_number, pc_name, ticks, salt, hash);
    if (token == 0) {
        wprintf(L"ERROR: CreateHash failed!\n");
        return false;
    }

    // Store current time so we can restore it later
    SYSTEMTIME org_time;
    GetSystemTime(&org_time);

    // Set to a predefined time because the driver checks the current time
    if (!SetSystemTime(&st)) {
        wprintf(L"ERROR: SetSystemTime failed!\n");
        return false;
    }

    DWORD dummy;
    BOOL success = DeviceIoControl(hDriver, IOCTL_AUTH, &token, sizeof(token), NULL, 0, &dummy, 0);
    if (!success) {
        wprintf(L"Last Error Code: %x \n", GetLastError());
        wprintf(L"ERROR: DeviceIoControl (auth) failed.\n");
        return false;
    }

    // Restore time
    if (!SetSystemTime(&org_time)) {
        wprintf(L"ERROR: SetSystemTime failed!\n");
        return false;
    }

    if (!success) {
        wprintf(L"ERROR: DeviceIoControl failed!\n");
        return false;
    }

    return true;
}

bool MoveMouse(HANDLE hDriver, int x, int y) {
    NF_MOUSE_REQUEST mouse_request = { 0 };
    mouse_request.x = x;
    mouse_request.y = y;
    mouse_request.button_flags = 0;
    DWORD dummy;
    BOOL success = DeviceIoControl(hDriver, IOCTL_MOUSE, &mouse_request, sizeof(mouse_request), NULL, 0, &dummy, 0);
    if (!success) {
        wprintf(L"Last Error Code: %x \n", GetLastError());
        wprintf(L"ERROR: DeviceIoControl failed.\n");
        return false;
    }

    return true;
}