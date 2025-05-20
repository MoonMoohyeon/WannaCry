// --- Metadata ---
// Function Name: decryptAESkey_4019E1
// Address: 0x4019E1
// Exported At: 20250520_114458
// Signature: unknown_signature
// ---------------
int __thiscall decryptAESkey_4019E1(int RSAKeyStruct, void *encryptedSource, size_t Size, void *decryptedData, int a5)
{
  BOOL v6; // eax
  struct _RTL_CRITICAL_SECTION *v8; // [esp-4h] [ebp-Ch]

  if ( !*(RSAKeyStruct + 8) )
    return 0;
  EnterCriticalSection((RSAKeyStruct + 16));
  v6 = CryptDecrypt(*(RSAKeyStruct + 8), 0, 1, 0, encryptedSource, &Size);// 이전에 암호화된 데이터 복호화 
  v8 = (RSAKeyStruct + 16);
  if ( !v6 )
  {
    LeaveCriticalSection(v8);
    return 0;
  }
  LeaveCriticalSection(v8);
  memcpy(decryptedData, encryptedSource, Size);
  *a5 = Size;
  return 1;
}
