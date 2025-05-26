// --- Metadata ---
// Function Name: loadFileToMemory_407A20
// Address: 0x407A20
// Exported At: 20250526_150814
// Signature: unknown_signature
// ---------------
int loadFileToMemory_407A20()
{
  int result; // eax
  int i; // edx
  const void *v2; // esi
  DWORD *v3; // edi
  HANDLE v4; // eax
  void *v5; // ebx
  DWORD v6; // eax
  DWORD *v7; // esi
  DWORD v8; // edi
  void *v9; // [esp-10h] [ebp-28h]
  DWORD NumberOfBytesRead; // [esp+Ch] [ebp-Ch] BYREF
  DWORD *v11; // [esp+10h] [ebp-8h]
  DWORD *v12; // [esp+14h] [ebp-4h]

  NumberOfBytesRead = 0;
  v11 = 0;
  v12 = 0;
  result = (int)GlobalAlloc(0x40u, (SIZE_T)&unk_50D800);// 파일을 메모리에 로딩 
  *(_DWORD *)&FileName[260] = result;
  if ( result )
  {
    *(_DWORD *)&FileName[264] = GlobalAlloc(0x40u, (SIZE_T)&unk_50D800);
    if ( *(_DWORD *)&FileName[264] )
    {
      for ( i = 0; i < 2; ++i )
      {
        v2 = &unk_40B020;
        if ( i )
          v2 = &unk_40F080;
        v3 = *(DWORD **)&FileName[4 * i + 260];
        (&v11)[i] = v3;
        qmemcpy(v3, v2, i != 0 ? 51364 : 16480);
        (&v11)[i] = (DWORD *)((char *)(&v11)[i] + (i != 0 ? 51364 : 16480));
      }
      v4 = CreateFileA(FileName, 0x80000000, 1u, 0, 3u, 4u, 0);
      v5 = v4;
      if ( v4 == (HANDLE)-1 )
      {
        GlobalFree(*(HGLOBAL *)&FileName[260]);
        GlobalFree(*(HGLOBAL *)&FileName[264]);
        result = 0;
      }
      else
      {
        v6 = GetFileSize(v4, 0);
        v7 = v11;
        v8 = v6;
        v9 = v11 + 1;
        *v11 = v6;
        ReadFile(v5, v9, v6, &NumberOfBytesRead, 0);
        if ( NumberOfBytesRead == v8 )
        {
          qmemcpy(v12, v7, v8 + 4);
          CloseHandle(v5);
          result = 1;
        }
        else
        {
          CloseHandle(v5);
          GlobalFree(*(HGLOBAL *)&FileName[260]);
          GlobalFree(*(HGLOBAL *)&FileName[264]);
          result = 0;
        }
      }
    }
    else
    {
      GlobalFree(*(HGLOBAL *)&FileName[260]);
      result = 0;
    }
  }
  return result;
}
