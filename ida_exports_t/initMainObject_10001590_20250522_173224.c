// --- Metadata ---
// Function Name: initMainObject_10001590
// Address: 0x10001590
// Exported At: 20250522_173224
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall initMainObject_10001590(_DWORD *mainObject)
{
  _DWORD *linkedListNode; // eax
  char v4; // [esp+Bh] [ebp-11h]

  initObject_10003A10((char *)mainObject + 4);  // 내부 객체의 생성자이자 초기 상태 세팅 함수 
  initObject_10003A10((char *)mainObject + 44);
  initVTableFuncPtr_10005D80((_BYTE *)mainObject + 84);
  mainObject[306] = 0;
  mainObject[307] = 0;
  mainObject[308] = 0;
  mainObject[309] = 0;
  *((_BYTE *)mainObject + 1248) = v4;
  linkedListNode = operator new(0x18u);
  *linkedListNode = linkedListNode;
  linkedListNode[1] = linkedListNode;
  mainObject[313] = linkedListNode;
  mainObject[314] = 0;
  mainObject[310] = 0;
  *((_WORD *)mainObject + 642) = 0;
  *((_WORD *)mainObject + 902) = 0;
  mainObject[581] = 0;
  mainObject[311] = 0;
  mainObject[582] = 0;
  mainObject[583] = 0;
  mainObject[584] = 0;
  *mainObject = &off_100071F8;
  return mainObject;
}
