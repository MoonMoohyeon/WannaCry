// --- Metadata ---
// Function Name: GrantAccessToEveryone_100013E0
// Address: 0x100013E0
// Exported At: 20250522_123626
// Signature: unknown_signature
// ---------------
HLOCAL __cdecl GrantAccessToEveryone_100013E0(HANDLE handle)
{
  PACL ppDacl; // [esp+Ch] [ebp-2Ch] BYREF
  PACL NewAcl; // [esp+10h] [ebp-28h] BYREF
  PSECURITY_DESCRIPTOR ppSecurityDescriptor; // [esp+14h] [ebp-24h] BYREF
  struct _EXPLICIT_ACCESS_A pListOfExplicitEntries; // [esp+18h] [ebp-20h] BYREF

  ppDacl = 0;                                   //  주어진 HANDLE 객체의 보안 DACL를 수정하여 모든 사용자("EVERYONE")에게 접근 권한을 부여
  NewAcl = 0;
  ppSecurityDescriptor = 0;
  GetSecurityInfo(handle, SE_KERNEL_OBJECT, 4u, 0, 0, &ppDacl, 0, &ppSecurityDescriptor);
  pListOfExplicitEntries.grfAccessPermissions = 2031617;
  pListOfExplicitEntries.grfAccessMode = GRANT_ACCESS;
  pListOfExplicitEntries.grfInheritance = 0;
  pListOfExplicitEntries.Trustee.pMultipleTrustee = 0;
  pListOfExplicitEntries.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
  pListOfExplicitEntries.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
  pListOfExplicitEntries.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  pListOfExplicitEntries.Trustee.ptstrName = "EVERYONE";
  SetEntriesInAclA(1u, &pListOfExplicitEntries, ppDacl, &NewAcl);
  SetSecurityInfo(handle, SE_KERNEL_OBJECT, 4u, 0, 0, NewAcl, 0);
  LocalFree(ppDacl);
  LocalFree(NewAcl);
  return LocalFree(ppSecurityDescriptor);
}
