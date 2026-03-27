from fastapi import FastAPI
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # React URL
    allow_methods=["GET"],
    allow_headers=["*"],
)

@app.get("/users")
def get_users():
    df=pd.read_csv("users.csv")

    return df.to_dict(orient="records")