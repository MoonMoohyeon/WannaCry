// --- Metadata ---
// Function Name: isPrivateIP_409110
// Address: 0x409110
// Exported At: 20250527_190734
// Signature: unknown_signature
// ---------------
BOOL __cdecl isPrivateIP_409110(u_long hostlong)
{
  u_long v1; // eax 다음 RFC1918 사설 IP 블록에 속하는지 검사
             //     
             //     10.0.0.0/8 (0x0A000000–0x0AFFFFFF)
             //     
             //     172.16.0.0/12 (0xAC100000–0xAC1FFFFF)
             //     
             //     192.168.0.0/16 (0xC0A80000–0xC0A8FFFF) 

  v1 = htonl(hostlong);
  if ( v1 >= 0xA000000 && v1 <= 0xAFFFFFF )
    return 1;
  if ( v1 >= 0xAC100000 && v1 <= 0xAC1FFFFF )
    return 1;
  return v1 >= 0xC0A80000 && v1 <= 0xC0A8FFFF;
}
