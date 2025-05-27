// --- Metadata ---
// Function Name: isIPInRange_4090D0
// Address: 0x4090D0
// Exported At: 20250527_190712
// Signature: unknown_signature
// ---------------
BOOL __cdecl isIPInRange_4090D0(u_long hostlong, u_long a2, u_long a3)
{
  u_long v3; // edi
  u_long v4; // esi
  BOOL result; // eax

  v3 = htonl(hostlong);                         // hostlong이 [a2, a3] 범위 내에 있는지를 확인 
  result = 0;
  if ( htonl(a2) <= v3 )
  {
    v4 = htonl(hostlong);
    if ( v4 <= htonl(a3) )
      result = 1;
  }
  return result;
}
