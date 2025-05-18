// --- Metadata ---
// Function Name: getTimestamp_406B23
// Address: 0x406B23
// Exported At: 20250518_111429
// Signature: unknown_signature
// ---------------
struct _FILETIME __cdecl getTimestamp_406B23(unsigned int a1, unsigned int a2)
{
  SYSTEMTIME SystemTime; // [esp+0h] [ebp-18h] BYREF MS-DOS 날짜 및 시간 형식을 Windows의 FILETIME 구조체로 변환 
  struct _FILETIME FileTime; // [esp+10h] [ebp-8h] BYREF

  SystemTime.wMilliseconds = 0;
  SystemTime.wYear = (a1 >> 9) + 1980;
  SystemTime.wDay = a1 & 0x1F;
  SystemTime.wMonth = (a1 >> 5) & 0xF;
  SystemTime.wHour = a2 >> 11;
  SystemTime.wSecond = 2 * (a2 & 0x1F);
  SystemTime.wMinute = (a2 >> 5) & 0x3F;
  SystemTimeToFileTime(&SystemTime, &FileTime);
  return FileTime;
}
