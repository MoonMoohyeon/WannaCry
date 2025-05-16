// --- Metadata ---
// Function Name: ReleaseCryptContext_4018B9
// Address: 0x4018B9
// Exported At: 20250516_090749
// Signature: unknown_signature
// ---------------
int __thiscall ReleaseCryptContext_4018B9(_DWORD *this)
{
  HCRYPTPROV v2; // eax

  if ( this[2] )
  {
    CryptDestroyKey(this[2]);                   // 키 제거 
    this[2] = 0;
  }
  if ( this[3] )
  {
    CryptDestroyKey(this[3]);
    this[3] = 0;
  }
  v2 = this[1];
  if ( v2 )
  {
    CryptReleaseContext(v2, 0);
    this[1] = 0;
  }
  return 1;
}
