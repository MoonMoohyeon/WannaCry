// --- Metadata ---
// Function Name: storeTwoValues_100018F0
// Address: 0x100018F0
// Exported At: 20250522_105055
// Signature: unknown_signature
// ---------------
int __thiscall storeTwoValues_100018F0(_DWORD *this, int a2, int a3)
{
  int result; // eax

  result = a2;                                  // 단순 멤버 변수 저장 
  this[583] = a2;
  this[582] = a3;
  return result;
}
