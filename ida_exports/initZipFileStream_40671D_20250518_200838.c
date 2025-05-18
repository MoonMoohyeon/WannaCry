// --- Metadata ---
// Function Name: initZipFileStream_40671D
// Address: 0x40671D
// Exported At: 20250518_200838
// Signature: unknown_signature
// ---------------
int __cdecl initZipFileStream_40671D(int sessionContext, unsigned __int8 *a2)
{
  int *v3; // esi
  void *v4; // eax
  bool v6; // zf
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // ecx
  int CRC32; // [esp+Ch] [ebp-Ch] BYREF
  int a4; // [esp+10h] [ebp-8h] BYREF
  int a3; // [esp+14h] [ebp-4h] BYREF
  unsigned __int8 *a1a; // [esp+20h] [ebp+8h]  ZIP 파일 내부의 개별 파일 항목을 처리하고 초기화 

  if ( !sessionContext || !*(sessionContext + 24) )// 인자 검사 및 기존 세션 닫기 
    return -102;
  if ( *(sessionContext + 124) )
    closeSession_406A97(sessionContext);
  if ( zipHeaderParsing_40657A(sessionContext, &CRC32, &a3, &a4) )// ZIP 헤더 파싱 
    return -103;
  v3 = malloc(0x84u);                           // 스트림 컨텍스트 구조체 할당 및 필드 초기화 
  if ( !v3 )
    return -104;
  v4 = malloc(0x4000u);
  *v3 = v4;
  v3[17] = a3;
  v3[18] = a4;
  v3[19] = 0;
  if ( !v4 )
  {
    free(v3);
    return -104;
  }
  v3[16] = 0;
  v6 = *(sessionContext + 52) == 0;
  v3[21] = *(sessionContext + 60);
  v3[20] = 0;
  v3[25] = *(sessionContext + 52);
  v3[24] = *sessionContext;
  v3[26] = *(sessionContext + 12);
  v3[6] = 0;
  if ( !v6 )                                    // 압축 세션 초기화 
  {
    v3[9] = 0;
    v3[10] = 0;
    v3[11] = 0;
    if ( !InitSession_405777((v3 + 1)) )
      v3[16] = 1;
  }
  v3[22] = *(sessionContext + 64);
  v3[23] = *(sessionContext + 68);
  *(v3 + 108) = *(sessionContext + 48) & 1;
  if ( (*(sessionContext + 48) & 8) != 0 )
    v7 = *(sessionContext + 56) >> 8;
  else
    v7 = HIBYTE(*(sessionContext + 60));
  *(v3 + 128) = v7;
  v8 = *(v3 + 108) != 0 ? 0xC : 0;              // 세부 플래그 설정 
  v3[29] = 591751049;
  v3[31] = v8;
  v3[28] = 305419896;
  v3[30] = 878082192;
  for ( a1a = a2; a1a; updateStreamState_405535(v3 + 28, *a1a++) )// 세션 상태 업데이트
  {
    if ( !*a1a )
      break;
  }
  v9 = *(sessionContext + 120);
  v10 = CRC32;
  v3[2] = 0;
  v3[15] = v9 + v10 + 30;                       // 오프셋 계산 및 세션 저장
  *(sessionContext + 124) = v3;
  return 0;
}
