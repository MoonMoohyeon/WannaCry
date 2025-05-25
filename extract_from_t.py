def extract_bytes(input_file, output_file, skip, count=None):
    with open(input_file, 'rb') as f:
        f.seek(skip)
        data = f.read(count if count else -1)
    with open(output_file, 'wb') as out:
        out.write(data)

extract_bytes("t.wnry", "encrypted_aes_key", skip=12, count=256)
extract_bytes("t.wnry", "large_chunk.bin", skip=280)
