// --- Metadata ---
// Function Name: GenerateRandomString_100014A0
// Address: 0x100014A0
// Exported At: 20250522_124027
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
