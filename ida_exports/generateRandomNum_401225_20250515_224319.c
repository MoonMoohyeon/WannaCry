// --- Metadata ---
// Function Name: generateRandomNum_401225
// Address: 0x401225
// Exported At: 20250515_224319
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
