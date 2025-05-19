// --- Metadata ---
// Function Name: LoadAndExecute_TwnryPayload_4021BD
// Address: 0x4021BD
// Exported At: 20250519_154025
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl LoadAndExecute_TwnryPayload_4021BD(void *decodedTwnryFile, int decodedTwnrySize)
{
  return sub_4021E9(                            // Twnry라는 내부 페이로드 파일을 메모리에 로드하고 실행하기 위한 진입점 
           decodedTwnryFile,                    // 함수 포인터를 전달하는 방식은 흔히 reflective DLL injection, unpacking, shellcode execution에서 사용되며, 분석을 어렵게 만드는 기법
           decodedTwnrySize,
           VirtualAlloc_40216E,
           VirtualFree_402185,
           LoadLibraryA_402198,
           GetProcAddress__beep,
           FreeLibrary_4021B2,
           0);
}
