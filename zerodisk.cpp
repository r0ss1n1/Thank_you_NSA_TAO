#include <stdio.h>
#include <Windows.h>
#include <winbase.h>
#include <stdint.h>
#include <strsafe.h>
#include <iostream>
#include <winioctl.h>
#define UNICODE 1
#define _UNICODE 1


/* Written by Charles T.W. Truscott */
/* Shout out to the National Security Agency, Tailored Access Operations, e2m2 directorate (NSA TAO EQUATION GROUP) and NSA TAO FEB (Forensics and Engineering Branch) */
/* I wrote this code, frequently using my OSCP foraging skills to come to an answer */
/* Thankfully nurtured for five years, three very intensive years, by the National Security Agency, United States of America */
/* Cryptanalytic check-in via nsa.gov, initially to recover stolen secrets */
/* Very much reaching a four year ambition of being anything like the NSA TAO Equation Group. In a 2014 Snowden leak, a NSA staffer describes a trip to New Zealand and authoring one software to exploit SSL, another to copy data to
	a secret partition for recovery later (stealth malware). I enjoyed reading the RTFM'ing on drives. Simple include of cryptographic headers could turn this into a fully-fledged unbreakable encryption software */
/* I was getting excited to keep this closed-source, to sell at $25 to $50 AUD, but know it won't really sell :-) */
/* Compiled with Visual Studio 2010 Academic on Windows 10 as per 2021 fully-updated and patched */
/* Next VS2019 Enterprise */
/* I first wanted to learn Windows API C++ in 2007. Glad to author something of note and has some untied ends */
/* I am beginning a software company at thievingmagpie.software. Will continue to distribute this open-source at zerodisk.app, later implementing DoD standard (don't remember the drive erasure standard code) */
/* Thanks, here's to NSA TAO for nurturing me for 5yrs intensively through cryptanalytics. Glad to keep the challenge coin I received so long as I live */

BOOL get_drive_geometry(LPCWSTR path, DISK_GEOMETRY * disk_geometry_structure) {
	printf("Entering function\n");
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	BOOL bResult = FALSE;
	DWORD junk = 0;
	hDevice = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if(hDevice == INVALID_HANDLE_VALUE) {
		printf("Error accessing disk\t%d\n", GetLastError());
		return FALSE;
	} else {
		printf("Access disk succeeded\n");
	}
	bResult = DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, disk_geometry_structure, sizeof(* disk_geometry_structure), &junk, (LPOVERLAPPED) NULL);
	if(!bResult) {
		printf("%d", GetLastError());
	}
	CloseHandle(hDevice);
	return (bResult);
}


int main(void) {
	DWORD my_drives = 200;
	char drive_strings[200];
	memset(drive_strings, 0, 200);
	DWORD GetDrives = GetLogicalDriveStringsW(my_drives, (LPWSTR) drive_strings);
	int drive_count;
	printf("WELCOME TO ZERODISK. COPYRIGHT CHARLES T.W. TRUSCOTT 2021\n");
	printf("thievingmagpie.software\tzerodisk.app\n\n");
	printf("#################### PLEASE SELECT A DRIVE ####################\n");
	printf("   ");
	for(drive_count = 0; drive_count <= 200; ++drive_count){
		printf("%c", drive_strings[drive_count]);
		if(drive_strings[drive_count] == 0x5C) {
			printf("\n\n");
		}
		if(drive_strings[drive_count] == 0x000 && drive_count > 80) {
			break;
		}
	}
	printf("\n");
	printf("###############################################################\n");
	char * drive_letter;
	printf("ENTER DRIVE LETTER (e.g. C, D, E, e.t.c.)\n");
	scanf("%s", drive_letter);
	char path[10];
	strcpy(path, "\\\\.\\");
	strcat(path, (char *) drive_letter);
	strcat(path, ":");
	wchar_t drive_path[10];
	for(int p = 0; p <= 10; ++p) {
		drive_path[p] = (wchar_t) path[p];
		printf("%c", path[p]);
	}
	LPCWSTR drive_path_access = drive_path;
	DISK_GEOMETRY dg = { 0 };
	get_drive_geometry(drive_path_access, &dg);
	wprintf(L"Bytes per sector: %ld\n", dg.BytesPerSector);
	ULONGLONG selected_drive_size = dg.Cylinders.QuadPart * (ULONG) dg.TracksPerCylinder * (ULONG) dg.SectorsPerTrack * (ULONG) dg.BytesPerSector;
	wprintf(L"%I64d bytes\n",  selected_drive_size);
	wprintf(L"%.2f GB\n", (double) selected_drive_size / (1024 * 1024 * 1024));
	Sleep(5000);
	HANDLE AccessDisk = CreateFileW(drive_path_access, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (AccessDisk == INVALID_HANDLE_VALUE) {
		printf("Cannot access disk, quitting\n");
		exit(1);
	}

	int limiting_value = 0;
	LARGE_INTEGER position = { 0 };
	BOOL get_file_pointer = SetFilePointerEx(AccessDisk, position, NULL, FILE_BEGIN);
	printf("\nScanning sector %I64u \n\n", position);
	BYTE read_buffer[65536];
	DWORD read;
	printf("\n############################## BYTES CONTAINED ##############################\n");
	BOOL read_disk = ReadFile(AccessDisk, read_buffer, 65536, &read, NULL);
	int read_limiting_value;
	for(read_limiting_value = 0; read_limiting_value <= 512; ++read_limiting_value) {
		printf("%x", read_buffer[read_limiting_value]);
	}
	BYTE zero_buffer[512];
	int zero_count;
	for(zero_count = 0; zero_count <= 512; ++zero_count) {
		BYTE zero_byte = 0;
		zero_buffer[zero_count] = zero_byte;
	}
	DWORD status;
	if(!DeviceIoControl(AccessDisk, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &status, NULL)){
		printf("Dismount failed\n%d", GetLastError());
	}
	int sectors_to_scan;
	printf("%I64d\n", selected_drive_size / 512);
	printf("%I64d\n", selected_drive_size / 512 / 100);
	for(limiting_value = 1; limiting_value <= (selected_drive_size / 512); ++limiting_value){
		LARGE_INTEGER position_again = { limiting_value * 512 };
		get_file_pointer = SetFilePointerEx(AccessDisk, position_again, NULL, FILE_BEGIN);
		BOOL write_to_disk = WriteFile(AccessDisk, zero_buffer, 512, NULL, NULL);
		printf("Writing to sector %I64u\t %lf percent done \t %I64u bytes left", position_again,(double) ((position_again.QuadPart + position_again.LowPart) / (selected_drive_size / 512 / 100)), selected_drive_size - (position_again.QuadPart + position_again.LowPart));

/*
		if(position_again < 0xFFFFFFFF) {
			printf("Writing to sector %I64u\t %lf percent done \t %I64u bytes left", position_again,(double) (position_again.LowPart / (selected_drive_size / 512 / 100)), selected_drive_size - position_again.LowPart);
		} else {
			break;
		}

*/
		printf("\n");
		if (write_to_disk == 0) {
			printf("Writing to sector %I64u failed\n", position);
			printf("%d\n", GetLastError());
		}


/*		int percent_done = 1;
		if((position_again.LowPart % selected_drive_size / 512 / 100) == 0) { 
			printf("%d percent completed\n");
			percent_done += 1;
			if(position_again.LowPart == selected_drive_size / 512) {
				break;
			}
		}
		if((position_again.QuadPart % selected_drive_size / 512 / 100) == 0) { 
			printf("%d percent completed\n");
			percent_done += 1;
			if(position_again.QuadPart == selected_drive_size / 512) {
				break;
			}
		}

*/
		Sleep(1);
	}
	CloseHandle(AccessDisk);
	return 0;
}