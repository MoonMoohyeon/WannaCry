// --- Metadata ---
// Function Name: SeekStreamOffset_405D0E
// Address: 0x405D0E
// Exported At: 20250517_204427
// Signature: unknown_signature
// ---------------
int __cdecl sub_405D0E(int streamObject, LONG offset, int origin)
{
  LONG v4; // ecx
  DWORD v5; // [esp-4h] [ebp-4h]

  if ( !*streamObject )
    goto LABEL_15;
  if ( !*(streamObject + 1) )
  {
    if ( *streamObject )
      return 29;
LABEL_15:
    if ( origin )
    {
      if ( origin == 1 )
      {
        *(streamObject + 28) += offset;
        return 0;
      }
      if ( origin != 2 )
        return 0;
      v4 = offset + *(streamObject + 24);
    }
    else
    {
      v4 = offset;
    }
    *(streamObject + 28) = v4;
    return 0;
  }
  if ( origin )
  {
    if ( origin == 1 )
    {
      v5 = 1;
LABEL_9:
      SetFilePointer(*(streamObject + 4), offset, 0, v5);
      return 0;
    }
    if ( origin == 2 )
    {
      v5 = 2;
      goto LABEL_9;
    }
    return 19;
  }
  SetFilePointer(*(streamObject + 4), offset + *(streamObject + 12), 0, 0);
  return 0;
}
