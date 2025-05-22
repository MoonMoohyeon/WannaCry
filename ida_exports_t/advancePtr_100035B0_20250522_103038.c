// --- Metadata ---
// Function Name: advancePtr_100035B0
// Address: 0x100035B0
// Exported At: 20250522_103038
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall advancePtr_100035B0(_DWORD **this, _DWORD *a2, int a3)
{
  _DWORD *v3; // edx
  _DWORD *result; // eax

  v3 = *this;
  *this = (_DWORD *)**this;                     // 연결리스트에서 다음 노드로 이동 후 이전 노드 저장 
  result = a2;
  *a2 = v3;
  return result;
}
