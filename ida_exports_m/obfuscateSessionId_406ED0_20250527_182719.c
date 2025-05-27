// --- Metadata ---
// Function Name: obfuscateSessionId_406ED0
// Address: 0x406ED0
// Exported At: 20250527_182719
// Signature: unknown_signature
// ---------------
unsigned int __cdecl obfuscateSessionId_406ED0(unsigned int a1)
{
  return (2 * a1) ^ (((HIWORD(a1) | a1 & 0xFF0000) >> 8) | (((a1 << 16) | a1 & 0xFF00) << 8));// 세션 아이디 난독화 
}
