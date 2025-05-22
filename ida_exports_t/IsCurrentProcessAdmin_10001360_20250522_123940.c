// --- Metadata ---
// Function Name: IsCurrentProcessAdmin_10001360
// Address: 0x10001360
// Exported At: 20250522_123940
// Signature: unknown_signature
// ---------------
BOOL IsCurrentProcessAdmin_10001360()
{
  BOOL result; // eax
  BOOL IsMember; // [esp+4h] [ebp-10h] BYREF
  PSID pSid; // [esp+8h] [ebp-Ch] BYREF
  struct _SID_IDENTIFIER_AUTHORITY pIdentifierAuthority; // [esp+Ch] [ebp-8h] BYREF

  pIdentifierAuthority.Value[0] = 0;
  pIdentifierAuthority.Value[1] = 0;
  pIdentifierAuthority.Value[2] = 0;
  pIdentifierAuthority.Value[3] = 0;
  pIdentifierAuthority.Value[4] = 0;
  pIdentifierAuthority.Value[5] = 5;
  IsMember = 0;
  result = AllocateAndInitializeSid(&pIdentifierAuthority, 2u, 0x20u, 0x220u, 0, 0, 0, 0, 0, 0, &pSid);
  if ( result )                                 // 현재 프로세스가 관리자 권한으로 실행중인지 확인 
  {
    if ( !CheckTokenMembership(0, pSid, &IsMember) )
      IsMember = 0;
    FreeSid(pSid);
    result = IsMember;
  }
  return result;
}
