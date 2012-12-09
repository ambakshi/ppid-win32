// AMB: Print out the parent PID. You can pass in -p <pid> to ask for
// the parent of a particular process
#define _WIN32_WINNT 0x0503
#include <windows.h>
#include <stdio.h>

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

LONG (WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle, ULONG ProcessInformationClass,
        PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength); 

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG  AllocationSize;
	ULONG  Size;
	ULONG  Flags;
	ULONG  DebugFlags;
	HANDLE  hConsole;
	ULONG  ProcessGroup;
	HANDLE  hStdInput;
	HANDLE  hStdOutput;
	HANDLE  hStdError;
	UNICODE_STRING  CurrentDirectoryName;
	HANDLE  CurrentDirectoryHandle;
	UNICODE_STRING  DllPath;
	UNICODE_STRING  ImagePathName;
	UNICODE_STRING  CommandLine;
	PWSTR  Environment;
	ULONG  dwX;
	ULONG  dwY;
	ULONG  dwXSize;
	ULONG  dwYSize;
	ULONG  dwXCountChars;
	ULONG  dwYCountChars;
	ULONG  dwFillAttribute;
	ULONG  dwFlags;
	ULONG  wShowWindow;
	UNICODE_STRING  WindowTitle;
	UNICODE_STRING  DesktopInfo;
	UNICODE_STRING  ShellInfo;
	UNICODE_STRING  RuntimeInfo;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void* PPEB_LDR_DATA;
typedef void* PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  BYTE                          Reserved4[104];
  PVOID                         Reserved5[52];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  PVOID                         Reserved7[1];
  ULONG                         SessionId;
} PEB, *PPEB;

struct PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress; 
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
};

ULONG_PTR GetParentProcessId(HANDLE hProcess) // By Napalm @ NetCore2K
{
    //ULONG_PTR pbi[6];
    //printf("size %d == %d\n", sizeof(pbi), sizeof(PROCESS_BASIC_INFORMATION));
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ulSize = 0;
    if(NtQueryInformationProcess){
        if(NtQueryInformationProcess(hProcess, 0,
                    &pbi, sizeof(pbi), &ulSize) >= 0 && ulSize == sizeof(pbi))
        {
            return (ULONG_PTR)pbi.Reserved3;
        }
    }
    return (ULONG_PTR)-1;
}


int main(int argc, char *argv[]) 
{   
    bool quiet = false;
    bool printTree = false;
    int i=1;
    ULONG_PTR ppid = 0;
    ULONG_PTR pid = GetCurrentProcessId();
    int levels = 0;
    while(i<argc)
    {
        if (!stricmp(argv[i],"-h"))
        {            
            fprintf(stderr,"Print the parent PID of the currently executing shell. Or pass in -p <pid> for another process.\nPass -n <levels> to go up that many levels.\n");
            fprintf(stderr,"\t%s [-q don't print PID] [-t print tree pppid:ppid:pid] [-p <pid>] [-n levels]\n\n", argv[0]);
            exit(0);
        } else if (!stricmp(argv[i],"-t")) {
            printTree = true;
        } else if (!stricmp(argv[i],"-q")) {
            quiet = true;
        } else if (!stricmp(argv[i],"-p")) {
            i++;
            if (i>=argc) {
                fprintf(stderr,"ERROR: No pid specified for -p\n");
                exit(-1);
            }
            pid = atoi(argv[i]);
            if (pid <= 0) {
                fprintf(stderr,"ERROR: Invalid pid specified for -p: %s\n", argv[i]);
                exit(-2);
            }
        } else if (!stricmp(argv[i],"-n")) {
            i++;
            if (i>=argc) {
                fprintf(stderr,"ERROR: No level specified for -n.\n");
                exit(-1);
            }
            levels = atoi(argv[i]);
            if (levels < 0) {
                fprintf(stderr,"ERROR: Invalid levels specified for -n: %s\n", argv[i]);
                exit(-2);
            }
        }
        
        i++;
    }
    
    *(FARPROC *)&NtQueryInformationProcess = 
        GetProcAddress(LoadLibraryA("NTDLL.DLL"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        fprintf(stderr,"ERROR: Unable to find NtQueryInformationProcess in NTDLL.DLL\n");
        exit(-1);
    }
    

    const ULONG_PTR starting_pid = pid;
    ULONG_PTR aPids[100] = {0};
    int nPids = 0;
    do {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION  ,FALSE,pid);
        if (!hProc){
            // we tried to go up too many levels in the tree
            if (ppid != 0)
                break;
            fprintf(stderr,"ERROR: Unable to open process %d to query information.\n", pid);
            exit(-3);
        }
        ppid = GetParentProcessId(hProc);
        CloseHandle(hProc);
        aPids[nPids++] = ppid;
        pid = ppid;        
        levels--;
    } while(levels >= 0);

    if (!quiet) {
        if (printTree) {
            for(int i=0; i < nPids; i++) {
                if (i < nPids - 1)
                    fprintf(stdout,"%d:",aPids[i]);
                else
                    fprintf(stdout,"%d\n",aPids[i]);
            }
        } else {
            fprintf(stdout,"%d\n", aPids[nPids-1]);
        }
    }

    return ppid;
}

