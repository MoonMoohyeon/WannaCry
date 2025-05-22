// --- Metadata ---
// Function Name: DecryptAndCleanupFiles_100027F0
// Address: 0x100027F0
// Exported At: 20250522_103533
// Signature: unknown_signature
// ---------------
int __thiscall DecryptAndCleanupFiles_100027F0(_DWORD *this, wchar_t *Format, int a3)
{
  _DWORD *v4; // eax 복호화 후 로그 기록 및 일부 파일 삭제 수행 
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
  DecryptFilesInDirectory_10002300(this, Format, (int)&v15, -1, a3);
  v5 = (void **)v16;
  for ( i = 2; i <= 4; ++i )                    // 상태별 복호화 재시도 루프 
  {
    v7 = *v5;
    if ( *v5 != v5 )
    {
      do
      {
        v8 = (_DWORD *)this[308];
        if ( v8 && *v8 )
          break;
        if ( decryptFileByState_10002940(this, (wchar_t *)v7 + 4, i) )
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
