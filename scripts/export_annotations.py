# export_annotations_v2.py
import json
import os
import time
import idaapi
import idautils
import idc

import git_sync

def export_annotations(folder="annotations"):
    # 폴더 없으면 생성
    if not os.path.exists(folder):
        os.makedirs(folder)

    # 파일 이름에 날짜, 시간 포함
    timestamp = time.strftime("%Y%m%d_%H%M")
    output_file = os.path.join(folder, f"annotations_{timestamp}.json")

    data = {
        'functions': [],
        'comments': []
    }

    for ea in idautils.Functions():
        func_name = idc.get_func_name(ea)
        func_cmt = idc.get_func_cmt(ea, 0) or ""
        data['functions'].append({
            'ea': ea,
            'name': func_name,
            'comment': func_cmt,
        })

    for seg_start in idautils.Segments():
        for head in idautils.Heads(seg_start, idc.get_segm_end(seg_start)):
            cmt = idc.get_cmt(head, 0)
            if cmt:
                data['comments'].append({
                    'ea': head,
                    'comment': cmt,
                })

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"[+] Annotations exported to {output_file}")

# Export 주석
export_annotations()

# Git Pull -> Commit -> Push
git_sync.git_pull()
git_sync.git_push()