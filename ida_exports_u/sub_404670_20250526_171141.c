// --- Metadata ---
// Function Name: sub_404670
// Address: 0x404670
// Exported At: 20250526_171141
// Signature: unknown_signature
// ---------------
void *__thiscall sub_404670(void *this, char a2)
{
  sub_404690(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}
