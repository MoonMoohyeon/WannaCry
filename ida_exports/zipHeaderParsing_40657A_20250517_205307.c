// --- Metadata ---
// Function Name: zipHeaderParsing_40657A
// Address: 0x40657A
// Exported At: 20250517_205307
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
  else if ( v12 != 67324752 )
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
