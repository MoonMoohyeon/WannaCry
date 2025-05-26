// --- Metadata ---
// Function Name: ChangeServiceConfig_407FA0
// Address: 0x407FA0
// Exported At: 20250526_150037
// Signature: unknown_signature
// ---------------
BOOL __cdecl ChangeServiceConfig_407FA0(SC_HANDLE hService, int a2)
{
  int v3[2]; // [esp+0h] [ebp-1Ch] BYREF
  int Info[5]; // [esp+8h] [ebp-14h] BYREF

  v3[0] = 1;
  Info[0] = 0;
  v3[1] = 1000 * a2;
  Info[3] = a2 != -1;
  Info[2] = (int)&unk_70F87C;
  Info[1] = (int)&unk_70F87C;
  Info[4] = (int)v3;
  return ChangeServiceConfig2A(hService, 2u, Info);
}
