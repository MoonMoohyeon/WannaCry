// --- Metadata ---
// Function Name: CryptGenRandomWrapper_10004420
// Address: 0x10004420
// Exported At: 20250522_170330
// Signature: unknown_signature
// ---------------
BOOL __thiscall CryptGenRandomWrapper_10004420(HCRYPTPROV *this, BYTE *pbBuffer, DWORD dwLen)
{
  return CryptGenRandom(this[1], dwLen, pbBuffer);
}
