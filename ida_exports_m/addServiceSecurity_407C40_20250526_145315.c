// --- Metadata ---
// Function Name: addServiceSecurity_407C40
// Address: 0x407C40
// Exported At: 20250526_145315
// Signature: unknown_signature
// ---------------
int addServiceSecurity_407C40()
{
  SC_HANDLE v0; // eax
  SC_HANDLE v1; // edi
  SC_HANDLE v2; // eax
  SC_HANDLE v3; // esi
  char Buffer[260]; // [esp+4h] [ebp-104h] BYREF

  sprintf(Buffer, "%s -m security", FileName);  // 서비스 등록 
  v0 = OpenSCManagerA(0, 0, 0xF003Fu);
  v1 = v0;
  if ( !v0 )
    return 0;
  v2 = CreateServiceA(v0, ServiceName, DisplayName, 0xF01FFu, 0x10u, 2u, 1u, Buffer, 0, 0, 0, 0, 0);
  v3 = v2;
  if ( v2 )
  {
    StartServiceA(v2, 0, 0);
    CloseServiceHandle(v3);
  }
  CloseServiceHandle(v1);
  return 0;
}
