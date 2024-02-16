#include <stdio.h>
#include <memoryapi.h>
#include <windows.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <cstdint>

#define JMP(frm,to) ((((uintptr_t)to) - ((uintptr_t)frm))-5)

typedef struct _FOUND_ADDRESSES
{
    UINT_PTR *Addresses;        
    UINT_PTR NumberOfAddresses; 
} FOUND_ADDRESSES, *PFOUND_ADDRESSES;

typedef struct _MODULE_RANGE
{
    UINT_PTR FirstAddress; 
    UINT_PTR LastAddress;  
} MODULE_RANGE, *PMODULE_RANGE;

HWND get_window_handle(const char *windowtitle)
{

    HWND kzwhandle = FindWindow(NULL, windowtitle); 
    if (kzwhandle == NULL)
    {
        printf("Didn't Find Game Window\n");
        return NULL;
    }
    else
    {
        printf("Handle For Game Window: %p\n  ", kzwhandle);
        return kzwhandle;
    }
}

HANDLE get_program_handle(DWORD processID)
{
    HANDLE program_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID); 
    if (program_handle == NULL)
    {
        printf("Didn't Find Process\n");
        return NULL;
    }
    else
    {
        printf("Handle For Process : %p\n  ", program_handle);
        return program_handle;
    }
}

HMODULE GetModule(HANDLE phandle)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    if (EnumProcessModules(phandle, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            CHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(phandle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                std::string ModName(szModName);
                std::string wstrModName = ModName;

                std::string wstrModContain = "Katana ZERO.exe"; 
                if (wstrModName.find(wstrModContain) != std::wstring::npos)
                {
                    CloseHandle(phandle);
                    return hMods[i];
                }
            }
        }
    }
    CloseHandle(phandle);
    return nullptr;
}


BOOLEAN
FindModuleRangeInProcess(
    DWORD ProcessId,
    LPCWSTR ModuleName,
    PMODULE_RANGE Range)
{
    
    if ((NULL == ModuleName) || (L'\0' == *ModuleName) || (NULL == ProcessId))
    {
        return FALSE;
    }

    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);

    if (NULL == hSnap)
    {
        return FALSE;
    }

    BOOLEAN bFoundModule = FALSE;
    BOOLEAN bFoundNextModule = FALSE;

    MODULEENTRY32W ME32;
    ZeroMemory(&ME32, sizeof(ME32));
    ME32.dwSize = sizeof(ME32);

    
    bFoundNextModule = Module32FirstW(hSnap, &ME32);
    while (TRUE == bFoundNextModule)
    {
        
        if (NULL == _wcsicmp(ModuleName, ME32.szModule))
        {
            Range->FirstAddress = (UINT_PTR)ME32.modBaseAddr;
            Range->LastAddress = (UINT_PTR)ME32.modBaseAddr + ME32.modBaseSize;
            bFoundModule = TRUE;
            break;
        }

        bFoundNextModule = Module32NextW(hSnap, &ME32);
    }

    CloseHandle(hSnap);

    if (TRUE == bFoundModule)
    {
        return TRUE;
    }

    return FALSE;
}


void cheatsel(HANDLE Hproc, DWORD64 Baseaddr, DWORD64 gettime,LPVOID V_newmem)
{
    int unlimittime = 0;
    //int unlimit_slowtime = 0; (Tired of doing this:))
    int enemy_cant_hit = 0;
    int noclip = 0;
    int noAI = 0;
    int selnum = 0;
    int loopnum = 0;
    std::cout << "Choose Your Hack:\n\n1.Unlimit Time\n2.Enemy can't Hit You\n3.Noclip (You May Fall Into Void)\n4.Disable AI\n5.Exit Trainer\n";
    for (loopnum; loopnum < 1;)
    {

        std::cin >> selnum; 
        switch (selnum)
        {

            //----------------------------- case1.unlimittime -------------------------------------//
            //  max1   newmem+0x200
            //  max2   newmem+0x208
            //  max3   newmem+0x210
            //  max4   newmem+0x218
            //  max5   newmem+0x220
            //  max6   newmem+0x228
            // return  gettime+6
            // check2  newmem+0x23
            // check3  newmem+0x
        case 1: 
            if (unlimittime == 0)
            {

                LPVOID   newmem = VirtualAllocEx(Hproc, NULL, 1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // 分配内存
                V_newmem = newmem;
                
                if (newmem == NULL)
                {
                    std::cerr << "Allocate Memory Error" << std::endl;
                }
                else
                {
                    std::cout << "newmem Address is: " << newmem << std::endl;
                }
                // label max1-max6

                //max1:
                BYTE max[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xAF, 0x40 };
                SIZE_T Byteswritten = 0;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0xE0, &max, sizeof(max), &Byteswritten);
                

                //max2:
                BYTE max2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0xB7, 0x40 };
                WriteProcessMemory(Hproc, (LPVOID)newmem+0xE8, &max2, sizeof(max), &Byteswritten);
                
                //max3:
                BYTE max3[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xA4, 0xBF, 0x40 };
                WriteProcessMemory(Hproc, (LPVOID)newmem+0xF0, &max3, sizeof(max), &Byteswritten);
                

                //max4:
                BYTE max4[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0xBB, 0x40 };
                WriteProcessMemory(Hproc, (LPVOID)newmem+0xF8, &max4, sizeof(max), &Byteswritten);
                

                //max5:
                BYTE max5[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0xC1, 0x40 };
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x100, &max5, sizeof(max), &Byteswritten);
                

                //max6:
                BYTE max6[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xC0, 0x40 };
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x108, &max6, sizeof(max), &Byteswritten);
                
                



                int jmp = 0xE9;
                int nop = 0x90;
                

                // label gettime
                uintptr_t JMP_value = JMP(gettime,newmem) ;
                WriteProcessMemory(Hproc, (LPVOID)gettime, &jmp, 1, &Byteswritten);   
                
                WriteProcessMemory(Hproc, (LPVOID)gettime + 0x1, &JMP_value, 4, &Byteswritten);  
                
                WriteProcessMemory(Hproc, (LPVOID)gettime + 0x5, &nop, 1, &Byteswritten);  
                

                // label newmem

                BYTE bytes[] = {
                                0x81, 0x7E, 0xF4, 0x00, 0x40, 0xAF, 0x40, 0x0F, 
                                0x85, 0x16, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7E, 
                                0x0D, 0xE0, 0x00, 0x64, 0x15, 0xF2, 0x0F, 0x11, 
                                0x0E, 0xE9, 0x06, 0xE1, 0x70, 0xEB, 0xE9, 0xE0, 
                                0xE0, 0x70, 0xEB};

                
                WriteProcessMemory(Hproc, (LPVOID)newmem, &bytes, sizeof(bytes), &Byteswritten);  
                
                long jmp_back_adr = Baseaddr + 0x1E124;  
                

                JMP_value = jmp_back_adr-(UINT_PTR)newmem-0x19-5 ;
                
                
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x1A, &JMP_value, 4, &Byteswritten);
                
                LPVOID Cmp_adr = newmem+0xE0;

                WriteProcessMemory(Hproc, (LPVOID)newmem+0x11, &Cmp_adr, 4, &Byteswritten);
                

                // label check2
                

                BYTE bytes_check2[] = {
                                        0x81, 0x7E, 0xF4, 0x00, 0x70, 0xB7, 0x40, 0x0F,      
                                        0x85, 0x16, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7E,      
                                        0x0D, 0xE8, 0x00, 0x64, 0x15, 0xF2, 0x0F, 0x11,      
                                        0x0E, 0xE9, 0xE3, 0xE0, 0x70, 0xEB, 0xE9, 0xBD,      
                                        0xE0, 0x70, 0xEB
                                    };

                WriteProcessMemory(Hproc, (LPVOID)newmem+0x23, &bytes_check2, sizeof(bytes_check2), &Byteswritten);
                
                JMP_value = JMP(newmem+0x3C,jmp_back_adr) ;

                

                WriteProcessMemory(Hproc, (LPVOID)newmem+0x3D, &JMP_value, 4, &Byteswritten);
                

                Cmp_adr = newmem+0xE8;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x34, &Cmp_adr, 4, &Byteswritten);

                // labet check3
                

               BYTE bytes_check3[] = {
                                        0x81, 0x7E, 0xF4, 0x00, 0xA4, 0xBF, 0x40, 0x0F,
                                        0x85, 0x16, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7E,
                                        0x0D, 0xF0, 0x00, 0x64, 0x15, 0xF2, 0x0F, 0x11,
                                        0x0E, 0xE9, 0xC0, 0xE0, 0x70, 0xEB, 0xE9, 0x9A,
                                        0xE0, 0x70, 0xEB
                                    };

                WriteProcessMemory(Hproc, (LPVOID)newmem+0x46, &bytes_check3, sizeof(bytes_check3), &Byteswritten);
                

                JMP_value = JMP(newmem+0x5F,jmp_back_adr) ;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x60, &JMP_value, 4, &Byteswritten);
                

                Cmp_adr = newmem+0xF0;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x57, &Cmp_adr, 4, &Byteswritten);

                // labet check4
                

               BYTE bytes_check4[] = {
                                        0x81, 0x7E, 0xF4, 0x00, 0x58, 0xBB, 0x40, 0x0F,
                                        0x85, 0x16, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7E,
                                        0x0D, 0xF8, 0x00, 0x64, 0x15, 0xF2, 0x0F, 0x11,
                                        0x0E, 0xE9, 0x9D, 0xE0, 0x70, 0xEB, 0xE9, 0x77,
                                        0xE0, 0x70, 0xEB
                                    };

                WriteProcessMemory(Hproc, (LPVOID)newmem+0x69, &bytes_check4, sizeof(bytes_check4), &Byteswritten);
                

                JMP_value = JMP(newmem+0x82,jmp_back_adr) ;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x83, &JMP_value, 4, &Byteswritten);
                

                Cmp_adr = newmem+0xF8;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x7A, &Cmp_adr, 4, &Byteswritten);


                // labet check5
                

               BYTE bytes_check5[] = {
                                        0x81, 0x7E, 0xF4, 0x00, 0x94, 0xC1, 0x40, 0x0F,
                                        0x85, 0x16, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7E,
                                        0x0D, 0x00, 0x01, 0x64, 0x15, 0xF2, 0x0F, 0x11,
                                        0x0E, 0xE9, 0x7A, 0xE0, 0x70, 0xEB, 0xE9, 0x54,
                                        0xE0, 0x70, 0xEB
                                    };

                WriteProcessMemory(Hproc, (LPVOID)newmem+0x8C, &bytes_check5, sizeof(bytes_check5), &Byteswritten);
                

                JMP_value = JMP(newmem+0xA5,jmp_back_adr) ;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0xA6, &JMP_value, 4, &Byteswritten);
                

                Cmp_adr = newmem+0x100;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0x9D, &Cmp_adr, 4, &Byteswritten);

                // labet check6

               BYTE bytes_check6[] = {
                                        0x81, 0x7E, 0xF4, 0x00, 0xCC, 0xC0, 0x40, 0x0F,
                                        0x85, 0x16, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7E,
                                        0x0D, 0x08, 0x01, 0x64, 0x15, 0xF2, 0x0F, 0x11,
                                        0x0E, 0xE9, 0x57, 0xE0, 0x70, 0xEB, 0xE9, 0x31,
                                        0xE0, 0x70, 0xEB
                                    };

                WriteProcessMemory(Hproc, (LPVOID)newmem+0xAF, &bytes_check6, sizeof(bytes_check6), &Byteswritten);
                

                JMP_value = JMP(newmem+0xC8,jmp_back_adr) ;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0xC9, &JMP_value, 4, &Byteswritten);
                

                Cmp_adr = newmem+0x108;
                WriteProcessMemory(Hproc, (LPVOID)newmem+0xC0, &Cmp_adr, 4, &Byteswritten);

                // labet code

               BYTE bytes_code[] = {
                                    0xF2, 0x0F, 0x11, 0x0E, 0xE9, 0x49, 0xE0, 0x70,
                                    0xEB, 0xE9, 0x23, 0xE0, 0x70, 0xEB
                                };

                WriteProcessMemory(Hproc, (LPVOID)newmem+0xD2, &bytes_code, sizeof(bytes_code), &Byteswritten);
                
                JMP_value = jmp_back_adr-(UINT_PTR)newmem-0xD6-5 ;

                WriteProcessMemory(Hproc, (LPVOID)newmem+0xD7, &JMP_value, 4, &Byteswritten);
               

                
        

                unlimittime = 1;

                std::cout << "UnlimitTime Enabled\n";
            }
            else if (unlimittime == 1)
            {
                SIZE_T Byteswritten = 0;
                BYTE Original_byte[] = {0xF2, 0x0F, 0x11, 0x0E, 0xEB, 0x21};
                WriteProcessMemory(Hproc, (LPVOID)gettime, &Original_byte, 6, &Byteswritten);
                
                VirtualFree(V_newmem, 0, MEM_RELEASE);
                unlimittime = 0;
                std::cout << "UnlimitTime Disabled\n";
            }
            break;

            //----------------------------- case3.enemy_cant_hit -------------------------------------//

        case 2: 
            if (enemy_cant_hit == 0)
            {

                SIZE_T Byteswritten = 0;
                int value3New = 0xC3;
                BOOL result = WriteProcessMemory(Hproc, (LPVOID)Baseaddr + 0x7E0F0, &value3New, 1, &Byteswritten);
                int errcode = GetLastError();
               

                enemy_cant_hit = 1;
                std::cout << "Enemy can't Hit Enabled\n";
            }

            //                     ---------------                   //

            else if (enemy_cant_hit == 1)
            {

                SIZE_T Byteswritten = 0;
                int value3Original = 0x55;
                WriteProcessMemory(Hproc, (LPVOID)Baseaddr + 0x7E0F0, &value3Original, 1, &Byteswritten);
                int errcode = GetLastError();
        

                enemy_cant_hit = 0;
                std::cout << "Enemy can't Hit Disabled\n\n";
            }

            break;

            //----------------------------- case4.noclip -------------------------------------//

        case 3: 
            if (noclip == 0)
            {

                SIZE_T Byteswritten = 0;
                int value3New = 0xC3;
                BOOL result = WriteProcessMemory(Hproc, (LPVOID)Baseaddr + 0xD2B50, &value3New, 1, &Byteswritten);
                int errcode = GetLastError();
                

                noclip = 1;
                std::cout << "Noclip Enabled\n";
            }

            //                     ---------------                   //

            else if (noclip == 1)
            {

                SIZE_T Byteswritten = 0;
                int value3Original = 0x55;
                WriteProcessMemory(Hproc, (LPVOID)Baseaddr + 0xD2B50, &value3Original, 1, &Byteswritten);
                int errcode = GetLastError();

                noclip = 0;
                std::cout << "Noclip Disabled\n";
            }
            break;

            //----------------------------- case5.noAI -------------------------------------//

        case 4: // 关闭敌人AI
            if (noAI == 0)
            {

                SIZE_T Byteswritten = 0;
                int value3New = 0xC3;
                BOOL result = WriteProcessMemory(Hproc, (LPVOID)Baseaddr + 0x1DD850, &value3New, 1, &Byteswritten);
                int errcode = GetLastError();

                noAI = 1;
                std::cout << "Enemy AI Disabled\n";
            }

            //                     ---------------                   //

            else if (noAI == 1)
            {

                SIZE_T Byteswritten = 0;
                int value3Original = 0x55;
                WriteProcessMemory(Hproc, (LPVOID)Baseaddr + 0x1DD850, &value3Original, 1, &Byteswritten);
                int errcode = GetLastError();

                noAI = 0;
                std::cout << "Enemy AI Enabled\n";
            }
            break;

            //----------------------------- case6 Exit -------------------------------------//

        case 5: 
            loopnum = 1;
            break;

        default:
            break;
        }
    }
}


BOOLEAN
FindAddressOfByteArrayWithDelimiters(
    PFOUND_ADDRESSES FoundAddresses,
    HANDLE ProcessHandle,
    BYTE *Data,
    INT DataSize,
    BOOLEAN SkipCompleteMatches,
    UINT_PTR FirstAddress,
    UINT_PTR LastAddress)
{
    if ((NULL == ProcessHandle) || (NULL == Data) || (NULL == DataSize))
    {
        return FALSE;
    }

    
    DWORD dwReadableMask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
    DWORD dwProtectedMask = (PAGE_GUARD | PAGE_NOACCESS);

    INT iFoundSize = 10;
    UINT_PTR ulCurrAddr = NULL;
    BYTE *lpBuff = NULL;
    SIZE_T ulBytesRead = NULL;

    MEMORY_BASIC_INFORMATION Mbi;
    ZeroMemory(&Mbi, sizeof(Mbi));

    FoundAddresses->Addresses = (UINT_PTR *)(malloc(iFoundSize * sizeof(UINT_PTR)));

    ulCurrAddr = (UINT_PTR)(FirstAddress);

    
    while ((sizeof(Mbi) == VirtualQueryEx(ProcessHandle, (LPVOID)(ulCurrAddr), &Mbi, sizeof(Mbi))),
           (ulCurrAddr <= LastAddress))
    {
        
        if ((dwReadableMask & Mbi.Protect) && (FALSE == (dwProtectedMask & Mbi.Protect)))
        {
            lpBuff = (BYTE *)(malloc(Mbi.RegionSize));

            if (TRUE == ReadProcessMemory(ProcessHandle, (LPVOID)(ulCurrAddr), lpBuff, Mbi.RegionSize,
                                          &ulBytesRead))
            {

                if (ulBytesRead == Mbi.RegionSize)
                {

                    for (UINT i = 0; i < Mbi.RegionSize; ++i)
                    {

                        if (0 == memcmp((LPCVOID)(lpBuff + i), Data, DataSize))
                        {
                            if (iFoundSize == (FoundAddresses->NumberOfAddresses + 1))
                            {
                                LPVOID lpTemp = realloc(FoundAddresses->Addresses, (iFoundSize += 50) * sizeof(UINT_PTR));

                                if (NULL == lpTemp)
                                {
                                    free(FoundAddresses->Addresses);
                                    free(lpBuff);

                                    return FALSE;
                                }

                                FoundAddresses->Addresses = (UINT_PTR *)(lpTemp);
                            }

                            FoundAddresses->Addresses[FoundAddresses->NumberOfAddresses] = (ulCurrAddr + i);

                            ++FoundAddresses->NumberOfAddresses;

                            if (TRUE == SkipCompleteMatches)
                            {
                                i += DataSize;
                            }
                        }
                    }
                }
            }

            free(lpBuff);
        }

        ulCurrAddr = (UINT_PTR)(Mbi.BaseAddress) + Mbi.RegionSize;
    }

    return TRUE;
}


BOOLEAN
FindAddressOfByteArrayInEntireProcess(
    PFOUND_ADDRESSES FoundAddresses,
    HANDLE ProcessHandle,
    BYTE *Data,
    INT DataSize,
    BOOLEAN SkipCompleteMatches)
{
    SYSTEM_INFO sysInfo;
    ZeroMemory(&sysInfo, sizeof(sysInfo));

    GetSystemInfo(&sysInfo);

    return FindAddressOfByteArrayWithDelimiters(FoundAddresses, ProcessHandle, Data, DataSize, SkipCompleteMatches,
                                                (UINT_PTR)sysInfo.lpMinimumApplicationAddress, (UINT_PTR)sysInfo.lpMaximumApplicationAddress);
}


BOOLEAN
FindAddressOfByteArrayInProcessModule(
    PFOUND_ADDRESSES FoundAddresses,
    HANDLE ProcessHandle,
    BYTE *Data,
    INT DataSize,
    BOOLEAN SkipCompleteMatches,
    LPCWSTR ModuleName)
{
    MODULE_RANGE modRange;
    ZeroMemory(&modRange, sizeof(modRange));

    DWORD dwProcId = GetProcessId(ProcessHandle);

    if (NULL == dwProcId)
    {
        return FALSE;
    }

    if (FALSE == FindModuleRangeInProcess(dwProcId, ModuleName, &modRange))
    {
        return FALSE;
    }

    return FindAddressOfByteArrayWithDelimiters(FoundAddresses, ProcessHandle, Data, DataSize, SkipCompleteMatches, modRange.FirstAddress,
                                                modRange.LastAddress);
}

int main()
{
    const char *window_title = "Katana ZERO";             
    HWND window_handle = get_window_handle(window_title); 

    DWORD processID;
    GetWindowThreadProcessId(window_handle, &processID); 
    printf("ProcessId is %x  ", processID);

    HANDLE program_handle = get_program_handle(processID); 
    HMODULE GetModule(HANDLE phandle);
    HMODULE Module = GetModule(program_handle);
    DWORD64 BaseAddress = (DWORD64)Module;
    if (Module == nullptr)
    {
        printf("Didn't Find Base Address\n");
    }
    else
        printf("Program Base Address is :%p\n", BaseAddress);

    FOUND_ADDRESSES faFound;
    ZeroMemory(&faFound, sizeof(faFound));

    LPCWSTR szModuleName = L"Katana ZERO.exe";

   

    program_handle = get_program_handle(processID);
    BYTE lpData[] = {0xF2, 0x0F, 0x11, 0x0E, 0xEB, 0x21}; 

    if (FALSE == FindAddressOfByteArrayInProcessModule(&faFound, program_handle, lpData, sizeof(lpData), TRUE, szModuleName))
    {
        printf("Didn't Find Any Address!\n");
    }

    else printf("Find Address! Is: \n", faFound.NumberOfAddresses);

    for (UINT i = NULL; i < faFound.NumberOfAddresses; ++i)
    {
        printf("0x%p\n", faFound.Addresses[i]);
    }
    DWORD64 gettime_adr = faFound.Addresses[0]; 

    free(faFound.Addresses);

    printf("---Press Any Key To Enable Hack---\n");
    getchar();
    LPVOID V_newmem = 0;
    cheatsel(program_handle, BaseAddress, gettime_adr,&V_newmem);


    CloseHandle(program_handle);
    return 0;
}
