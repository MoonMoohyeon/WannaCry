// --- Metadata ---
// Function Name: importKeyAndVerify_10004500
// Address: 0x10004500
// Exported At: 20250522_123918
// Signature: unknown_signature
// ---------------
int __cdecl importKeyAndVerify_10004500(int a1)
{
  int v1; // eax
  char v3[40]; // [esp+4h] [ebp-68h] BYREF
  char Buffer[52]; // [esp+2Ch] [ebp-40h] BYREF
  int v5; // [esp+68h] [ebp-4h]

  sprintf(Buffer, "%08X.dky", a1);
  if ( GetFileAttributesA(Buffer) != -1 && GetFileAttributesA(pky_1000DD24) != -1 )
  {
    initObject_10003A10(v3);
    v5 = 0;
    v1 = VerifyKeyPair_10003D10((int)v3, pky_1000DD24, Buffer);// 키 쌍을 가져온 후 검증 
    v5 = -1;
    if ( v1 )
    {
      DeleteCriticalSection_10003A60(v3);
      return 1;
    }
    DeleteCriticalSection_10003A60(v3);
  }
  return 0;
}
