// --- Metadata ---
// Function Name: EncryptByteWithState_4055A3
// Address: 0x4055A3
// Exported At: 20250517_142314
// Signature: unknown_signature
// ---------------
unsigned __int8 __cdecl EncryptByteWithState_4055A3(int *a1, char targetbyte)
{
  unsigned __int8 targetbytea; // [esp+Ch] [ebp+Ch]

  targetbytea = getNextStreamByte_405588(a1) ^ targetbyte;// 상태 기반 스트림 암호화 수행 
  updateStreamState_405535(a1, targetbytea);
  return targetbytea;
}
