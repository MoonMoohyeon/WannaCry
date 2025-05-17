// --- Metadata ---
// Function Name: updateStreamState_405535
// Address: 0x405535
// Exported At: 20250517_142305
// Signature: unknown_signature
// ---------------
int __cdecl sub_405535(int *unit, unsigned __int8 a2)
{
  int nextCRCstate; // eax
  unsigned int v3; // esi
  unsigned int seedLCG; // eax
  int CRClike; // eax

  nextCRCstate = (*unit >> 8) ^ dword_40D054[a2 ^ *unit];
  v3 = unit[2];
  *unit = nextCRCstate;
  seedLCG = 134775813 * (unit[1] + nextCRCstate) + 1;
  unit[1] = seedLCG;
  CRClike = (v3 >> 8) ^ dword_40D054[v3 ^ HIBYTE(seedLCG)];
  unit[2] = CRClike;
  return CRClike;
}
