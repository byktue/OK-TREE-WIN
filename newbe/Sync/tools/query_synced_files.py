import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parents[1] / 'file_server.db'
if not DB.exists():
    print('file_server.db 未找到：', DB)
    raise SystemExit(1)

conn = sqlite3.connect(str(DB))
cur = conn.cursor()
# 查询最近上传的 sync_test_* 文件
cur.execute("SELECT id, filename, filepath, filesize, md5, uploader_id, upload_time, is_deleted FROM files WHERE filename LIKE 'sync_test_%' ORDER BY upload_time DESC")
rows = cur.fetchall()
if not rows:
    print('未在 files 表中找到 sync_test_* 记录')
else:
    print('找到以下记录（按 upload_time 降序）：')
    for r in rows:
        print('- id:', r[0])
        print('  filename:', r[1])
        print('  filepath:', r[2])
        print('  filesize:', r[3])
        print('  md5:', r[4])
        print('  uploader_id:', r[5])
        print('  upload_time:', r[6])
        print('  is_deleted:', r[7])
        print('  physical path exists:', Path(r[2]).exists())
        print()

cur.close()
conn.close()