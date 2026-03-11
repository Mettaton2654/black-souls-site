import traceback
from app import app

client = app.test_client()

for path in ['/', '/post/1']:
    try:
        r = client.get(path)
        print(f"{path} -> {r.status_code}")
        if r.status_code != 200:
            print(r.data.decode('utf-8', 'ignore')[:2000])
    except Exception as e:
        print(f"{path} -> EXCEPTION")
        traceback.print_exc()
