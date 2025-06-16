#ifndef MOUSE_H
#define MOUSE_H

#include <stdio.h>
#include <windows.h>
#include <stdbool.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
NTSTATUS NTAPI RtlGetVersion(RTL_OSVERSIONINFOW* lpVersionInformation);

#define IOCTL_MOUSE 0x617F862C
#define IOCTL_AUTH 0x8F67D7B0

typedef struct {
    long x;
    long y;
    unsigned short button_flags;
} NF_MOUSE_REQUEST;

bool DriverAuth(HANDLE hDriver);
bool MoveMouse(HANDLE hDriver, int x, int y);

#endif