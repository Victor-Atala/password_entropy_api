# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
import logic  # AHORA SÍ FUNCIONARÁ ESTE IMPORT
import uvicorn # Necesario para correrlo desde código

breached_db = set()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global breached_db
    print("--- INICIANDO SISTEMA DE SEGURIDAD ---")
    breached_db = logic.load_breached_passwords("passwords.csv")
    print(f"Base de datos cargada: {len(breached_db)} entradas.")
    yield
    breached_db.clear()
    print("--- SISTEMA APAGADO ---")

app = FastAPI(lifespan=lifespan)

class PasswordRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024)

class EvaluationResponse(BaseModel):
    length_L: int
    pool_size_N: int
    entropy_bits: float
    strength: str
    crack_time_estimate: str
    is_common_password: bool

@app.post("/api/v1/password/evaluate", response_model=EvaluationResponse)
async def evaluate_password(input: PasswordRequest):
    pwd = input.password
    try:
        L = len(pwd)
        N = logic.calculate_N(pwd)
        entropy = logic.calculate_entropy(pwd)
        crack_time = logic.estimate_crack_time(entropy)
        is_breached = pwd in breached_db
        strength = logic.evaluate_strength(entropy, is_breached)

        return EvaluationResponse(
            length_L=L,
            pool_size_N=N,
            entropy_bits=entropy,
            strength=strength,
            crack_time_estimate=crack_time,
            is_common_password=is_breached
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno.")

# --- ESTO ES LO QUE TE FALTABA PARA EJECUTAR CON "python main.py" ---
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)