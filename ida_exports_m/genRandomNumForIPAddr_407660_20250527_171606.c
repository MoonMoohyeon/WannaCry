// --- Metadata ---
// Function Name: genRandomNumForIPAddr_407660
// Address: 0x407660
// Exported At: 20250527_171606
// Signature: unknown_signature
// ---------------
int __thiscall genRandomNumForIPAddr_407660(void *this)
{
  BYTE pbBuffer[4]; // [esp+0h] [ebp-4h] BYREF

  *pbBuffer = this;
  if ( !*&FileName[272] )
    return rand();
  EnterCriticalSection(&CriticalSection);
  CryptGenRandom(*&FileName[272], 4u, pbBuffer);// 랜덤 숫자를 생성 
  LeaveCriticalSection(&CriticalSection);
  return *pbBuffer;
}
