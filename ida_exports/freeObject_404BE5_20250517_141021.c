// --- Metadata ---
// Function Name: freeObject_404BE5
// Address: 0x404BE5
// Exported At: 20250517_141021
// Signature: unknown_signature
// ---------------
int __cdecl freeObject_404BE5(_DWORD *a1, int a2)
{
  initObject_4042C0(a1, a2, 0);
  (*(a2 + 36))(*(a2 + 40), a1[10]);             // 내부 포인터 해제, 콜백 기반 
  (*(a2 + 36))(*(a2 + 40), a1[9]);
  (*(a2 + 36))(*(a2 + 40), a1);
  return 0;
}
