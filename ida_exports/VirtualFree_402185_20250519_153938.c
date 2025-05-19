// --- Metadata ---
// Function Name: VirtualFree_402185
// Address: 0x402185
// Exported At: 20250519_153938
// Signature: unknown_signature
// ---------------
BOOL __cdecl VirtualFree_402185(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
  return VirtualFree(lpAddress, dwSize, dwFreeType);
}
