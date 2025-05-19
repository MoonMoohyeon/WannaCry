// --- Metadata ---
// Function Name: ApplyMemoryProtection_40267B
// Address: 0x40267B
// Exported At: 20250519_162341
// Signature: unknown_signature
// ---------------
BOOL __cdecl ApplyMemoryProtection_40267B(int a1, DWORD flOldProtect)
{
  SIZE_T memorySize; // ebx
  BOOL result; // eax
  unsigned int v4; // ecx
  unsigned int v5; // esi
  DWORD v6; // edx

  memorySize = *(flOldProtect + 8);             // 조건적으로 메모리 보호 변경 또는 해제 
  if ( !memorySize )
    return 1;
  v4 = *(flOldProtect + 12);
  if ( (v4 & 0x2000000) != 0 )                  // 0x2000000 플래그가 있는 경우 
  {
    if ( *flOldProtect == *(flOldProtect + 4) )
    {
      if ( *(flOldProtect + 16) || (v5 = *(a1 + 56), *(*a1 + 56) == v5) || !(memorySize % v5) )
        (*(a1 + 32))(*flOldProtect, memorySize, 0x4000, *(a1 + 48));
    }
    result = 1;
  }
  else                                          // 조건 불만족 시 Virtual Protect 호출 
  {
    v6 = flNewProtect[4 * ((v4 >> 29) & 1) + 2 * ((v4 >> 30) & 1) + (v4 >> 31)];
    if ( (v4 & 0x4000000) != 0 )
      BYTE1(v6) |= 2u;
    result = VirtualProtect(*flOldProtect, memorySize, v6, &flOldProtect);
  }
  return result;
}
