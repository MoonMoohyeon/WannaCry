// --- Metadata ---
// Function Name: ResolveAndBindDLL&API_4027DF
// Address: 0x4027DF
// Exported At: 20250519_160718
// Signature: unknown_signature
// ---------------
int __cdecl ResolveAndBindDLL_API_4027DF(_DWORD *a1)
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
