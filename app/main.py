from fastapi import FastAPI, Response

app = FastAPI()


@app.get("/ping")
def ping():
    return Response(content="PONG from quick-test-apis", media_type="text/plain")

@app.get("/nginx-502")
def nginx_502():
    html_content = """<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx</center>
</body>
</html>"""
    return Response(content=html_content, media_type="text/html", status_code=502)

@app.get("/raw-json-simple")
def raw_json_simple():
    raw_json = """{"status": "ok", "content": "This is a json with no pretty-formatting"}"""
    return Response(content=raw_json, media_type="application/json")
