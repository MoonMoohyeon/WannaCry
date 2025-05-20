// --- Metadata ---
// Function Name: DecodeDosDateTime_406191
// Address: 0x406191
// Exported At: 20250520_133047
// Signature: unknown_signature
// ---------------
unsigned int __cdecl DecodeDosDateTime_406191(unsigned int dosDateTime, _DWORD *outFields)
{
  unsigned int result; // eax

  outFields[3] = BYTE2(dosDateTime) & 0x1F;
  outFields[5] = (HIWORD(dosDateTime) >> 9) + 1980;
  outFields[2] = dosDateTime >> 11;
  result = (dosDateTime >> 5) & 0x3F;
  outFields[4] = ((dosDateTime >> 21) & 0xF) - 1;
  outFields[1] = result;
  *outFields = 2 * (dosDateTime & 0x1F);
  return result;
}
