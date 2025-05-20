// --- Metadata ---
// Function Name: CreateFileReaderContext_405BAE
// Address: 0x405BAE
// Exported At: 20250520_130202
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
