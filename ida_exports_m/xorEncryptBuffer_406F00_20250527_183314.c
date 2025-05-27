// --- Metadata ---
// Function Name: xorEncryptBuffer_406F00
// Address: 0x406F00
// Exported At: 20250527_183314
// Signature: unknown_signature
// ---------------
int __cdecl xorEncryptBuffer_406F00(int a1, int a2, int a3)
{
  int v3; // eax
  int v5; // [esp+4h] [ebp-8h]
  char v6; // [esp+8h] [ebp-4h]

  v3 = 0;
  v6 = 0;
  v5 = a1;
  if ( a3 <= 0 )                                // 4바이트 키 (int key)를 이용한 XOR 스트림 암호화 
    return 0;
  do
  {
    *(v3 + a2) ^= *(&v5 + v3 % 4);
    ++v3;
  }
  while ( v3 < a3 );
  return 0;
}
