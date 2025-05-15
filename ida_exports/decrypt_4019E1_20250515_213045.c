// --- Metadata ---
// Function Name: decrypt_4019E1
// Address: 0x4019E1
// Exported At: 20250515_213045
// Signature: unknown_signature
// ---------------
int __thiscall decrypt_4019E1(int this, void *encryptedSource, size_t Size, void *decryptedData, int a5)
{
  BOOL v6; // eax
  struct _RTL_CRITICAL_SECTION *v8; // [esp-4h] [ebp-Ch]

  if ( !*(this + 8) )
    return 0;
  EnterCriticalSection((this + 16));
  v6 = CryptDecrypt(*(this + 8), 0, 1, 0, encryptedSource, &Size);
  v8 = (this + 16);
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
