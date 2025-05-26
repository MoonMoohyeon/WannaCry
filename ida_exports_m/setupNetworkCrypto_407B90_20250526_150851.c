// --- Metadata ---
// Function Name: setupNetworkCrypto_407B90
// Address: 0x407B90
// Exported At: 20250526_150851
// Signature: unknown_signature
// ---------------
int setupNetworkCrypto_407B90()
{
  struct WSAData WSAData; // [esp+0h] [ebp-190h] BYREF

  if ( WSAStartup(0x202u, &WSAData) )           // 네트워크 기능 초기화 
    return 0;
  initializeCryptoContext_407620();
  return loadFileToMemory_407A20();
}
