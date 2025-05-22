// --- Metadata ---
// Function Name: GenerateAndEncryptRandomData_10004370
// Address: 0x10004370
// Exported At: 20250522_101558
// Signature: unknown_signature
// ---------------
BOOL __thiscall GenerateAndEncryptRandomData_10004370(int this, BYTE *pbBuffer, DWORD dwLen, int pbData, int encryptedBufferInfo)
{
  BOOL result; // eax
  BYTE *dstDataPtr; // ebp
  DWORD *encryptedSizePtr; // edi
  BOOL v9; // eax
  struct _RTL_CRITICAL_SECTION *v10; // [esp+0h] [ebp-14h]

  if ( !*(_DWORD *)(this + 8) )
    return 0;
  result = CryptGenRandomWrapper_10004420((HCRYPTPROV *)this, pbBuffer, dwLen);// 랜덤 데이터를 생성하고, 이를 암호화하여 출력 버퍼에 저장
  if ( result )
  {
    dstDataPtr = (BYTE *)pbData;
    if ( pbData && encryptedBufferInfo )
    {
      qmemcpy((void *)pbData, pbBuffer, dwLen);
      EnterCriticalSection((LPCRITICAL_SECTION)(this + 16));
      encryptedSizePtr = (DWORD *)encryptedBufferInfo;
      v9 = CryptEncrypt(*(_DWORD *)(this + 8), 0, 1, 0, dstDataPtr, &dwLen, *(_DWORD *)encryptedBufferInfo);
      v10 = (struct _RTL_CRITICAL_SECTION *)(this + 16);
      if ( !v9 )
      {
        LeaveCriticalSection(v10);
        return 0;
      }
      LeaveCriticalSection(v10);
      *encryptedSizePtr = dwLen;
    }
    result = 1;
  }
  return result;
}
