import ssdeep
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import sys
import os

# 기본 이름 및 해시값
names = [
    "origianl dropper module", "original ransom module",
    "1.1 dropper module", "1.2 ransom module",
    "2.1 dropper module", "2.2 ransom module",
    "3.1 dropper module", "3.2 ransom module",
    "4.1 dropper module", "4.2 ransom module",
    "5.1 dropper module", "5.2 ransom module",
    "6.1 dropper module", "6.2 ransom module",
    "7.1 dropper module", "7.2 ransom module",
    "8.1 dropper module", "8.2 ransom module",
    "9.1 dropper module", "9.2 ransom module"
]

hashes = [
    "98304:wDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2g3R:wDqPe1Cxcxk3ZAEUadzR8yc4gB",
    "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2g3x:QqPe1Cxcxk3ZAEUadzR8yc4gB",
    "98304:Z8qPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2HI:Z8qPe1Cxcxk3ZAEUadzR8yc4HI",
    "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2Hj:QqPe1Cxcxk3ZAEUadzR8yc4Hj",
    "98304:yDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2HI:yDqPe1Cxcxk3ZAEUadzR8yc4HI",
    "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2Hj:QqPe1Cxcxk3ZAEUadzR8yc4Hj",
    "98304:XDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2HI:XDqPe1Cxcxk3ZAEUadzR8yc4HI",
    "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2Hj:QqPe1Cxcxk3ZAEUadzR8yc4Hj",
    "49152:QnpENbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvn:Qp+oBhz1aRxcSUDk36SAEdhvn",
    "49152:XENbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvm:X+oBhz1aRxcSUDk36SAEdhvm",
    "49152:QnsEMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvn:QfPoBhz1aRxcSUDk36SAEdhvn",
    "49152:SEMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvm:ZPoBhz1aRxcSUDk36SAEdhvm",
    "12288:GvbLgPlu+QhMbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+D:2bLgddQhfdmMSirYbcMNgef0",
    "12288:nQhMbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+D:nQhfdmMSirYbcMNgef0",
    "98304:XDqPoBhz1aRxcSUDk36SAEdhvxWa9P593N:XDqPe1Cxcxk3ZAEUadzN",
    "98304:QqPoBhz1aRxcSUDk36SAEdhvxWa9P593K:QqPe1Cxcxk3ZAEUadzK",
    "49152:2nAQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAA:yDqPoBhz1aRxcSUDk36SA",
    "49152:nQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAAL:QqPoBhz1aRxcSUDk36SA8",
    "49152:QnpE/bcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvn:Qp4oBhz1aRxcSUDk36SAEdhvn",
    "49152:XE/bcBVQej/1INRx+TSqTdX1HkQo6SAARdhnvm:X4oBhz1aRxcSUDk36SAEdhvm"
]

# 이름과 해시를 딕셔너리로 구성
hash_dict = dict(zip(names, hashes))

# 인자가 있을 경우 추가 처리
if len(sys.argv) >= 2:
    target_file = sys.argv[1]

    if os.path.isfile(target_file):
        with open(target_file, "rb") as f:
            file_bytes = f.read()
            file_hash = ssdeep.hash(file_bytes)
        
        user_name = f"user input: {os.path.basename(target_file)}"
        names.append(user_name)
        hash_dict[user_name] = file_hash
        print(f"[+] {user_name} 해시 추가됨.")
    else:
        print(f"[!] '{target_file}' 파일을 찾을 수 없습니다. 기본 데이터만 시각화합니다.")

# 유사도 행렬 계산
matrix = pd.DataFrame(index=names, columns=names)

for i in names:
    for j in names:
        matrix.loc[i, j] = ssdeep.compare(hash_dict[i], hash_dict[j])

# 오류 방지를 위해 float → int
matrix = matrix.astype(float).fillna(0).round(0).astype(int)

# 히트맵 시각화
sns.set(style="whitegrid")
plt.figure(figsize=(12, 10))
sns.heatmap(matrix, annot=True, cmap="Reds", fmt="d", cbar_kws={"label": "Similarity (%)"})
plt.title("SSDEEP Similarity Heatmap")
plt.xticks(rotation=90)
plt.tight_layout()
plt.show()
