#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "mouse.h"

int main() {
	HANDLE driver_handle = CreateFileW(L"\\\\.\\JustWokeUp", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (driver_handle == INVALID_HANDLE_VALUE) {
		wprintf(L"Last Error Code: %x \n", GetLastError());
		wprintf(L"ERROR: CreateFileA failed! Make sure that the driver is loaded.\n");
		getchar();
		return 1;
	}

	if (!DriverAuth(driver_handle)) {
		wprintf(L"ERROR: DriverAuth failed!\n");
		getchar();
		return 1;
	}

	while (true) {
		wprintf(L"Moving the mouse...\n");

		if (!MoveMouse(driver_handle, 100, 100)) {
			getchar();
			return 1;
		}

		Sleep(1500);
	}

	return 0;
}