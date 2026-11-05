import os

from fastapi import FastAPI

app = FastAPI()


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/items/{item_id}")
def item(item_id: int):
    return {"id": item_id, "db": bool(os.environ.get("DATABASE_URL"))}
