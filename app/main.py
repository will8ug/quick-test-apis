from fastapi import FastAPI, Response

app = FastAPI()


@app.get("/ping")
def ping():
    return Response(content="PONG from quick-test-apis", media_type="text/plain")

