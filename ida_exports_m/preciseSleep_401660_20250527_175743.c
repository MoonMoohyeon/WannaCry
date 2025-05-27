// --- Metadata ---
// Function Name: preciseSleep_401660
// Address: 0x401660
// Exported At: 20250527_175743
// Signature: unknown_signature
// ---------------
void __cdecl preciseSleep_401660(LARGE_INTEGER a1)
{
  int v1; // edi
  signed int v2; // esi
  unsigned int v3; // ebp
  signed int v4; // ebx
  LARGE_INTEGER v5; // rdi
  LARGE_INTEGER PerformanceCount; // [esp+Ch] [ebp-10h] BYREF
  LARGE_INTEGER Frequency; // [esp+14h] [ebp-8h] BYREF

  v1 = a1.QuadPart / 1000000;
  v2 = 1000 * (a1.QuadPart % 1000000);
  a1.LowPart = v2;
  if ( v1 > 0 )                                 // 정확한 지연(sleep)을 위해 성능 타이머(QueryPerformanceCounter)와 일반 슬립을 조합한 고정밀 Sleep 함수 
  {
    Sleep(v2 / 1000000 + 1000 * v1);
    return;
  }
  if ( dbl_431450 == 0.0 )
  {
    if ( !QueryPerformanceFrequency(&Frequency) )
    {
      Sleep(v2 / 1000000);
      return;
    }
    dbl_431450 = Frequency.QuadPart * 0.000000001;
  }
  a1.HighPart = (a1.LowPart * dbl_431450) >> 32;
  v3 = (a1.LowPart * dbl_431450);
  v4 = v2 / 1000000 - 10;
  QueryPerformanceCounter(&PerformanceCount);
  v5.QuadPart = __PAIR64__(a1.HighPart, v3) + PerformanceCount.QuadPart;
  if ( v4 > 0 )
    Sleep(v4);
  QueryPerformanceCounter(&a1);
  while ( a1.QuadPart < v5.QuadPart )
    QueryPerformanceCounter(&a1);
}
