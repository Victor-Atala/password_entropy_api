from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
import logic

# --- BASE DE DATOS EN MEMORIA (Diccionario) ---
# Se carga al iniciar, se borra al apagar.
breached_db = set()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # FASE DE CARGA
    global breached_db
    print("--- INICIANDO SISTEMA DE SEGURIDAD ---")
    print("Cargando diccionario de contraseñas comprometidas...")
    # Solo leemos la columna 2 del CSV, como pide la actividad
    breached_db = logic.load_breached_passwords("passwords.csv")
    print(f"Base de datos cargada: {len(breached_db)} entradas en memoria RAM.")
    
    yield  # La API corre aquí
    
    # FASE DE LIMPIEZA (Cero Persistencia)
    breached_db.clear()
    print("--- SISTEMA APAGADO: Memoria limpiada ---")

app = FastAPI(
    title="Evaluador de Entropía de Contraseñas",
    description="API RESTful para análisis de fortaleza criptográfica. Cero persistencia.",
    version="1.0.0",
    lifespan=lifespan
)

# --- MODELOS DE DATOS CON VALIDACIÓN ---
class PasswordRequest(BaseModel):
    # VALIDACIÓN DE ENTRADA:
    # 1. min_length=1: Evita cadenas vacías.
    # 2. max_length=1024: Evita ataques de Desbordamiento de Búfer o DoS por CPU.
    password: str = Field(..., min_length=1, max_length=1024, description="La contraseña a evaluar")

class EvaluationResponse(BaseModel):
    length_L: int
    pool_size_N: int
    entropy_bits: float
    strength: str
    crack_time_estimate: str
    is_common_password: bool

# --- ENDPOINT (La lógica de negocio) ---
@app.post("/api/v1/password/evaluate", response_model=EvaluationResponse)
async def evaluate_password(input: PasswordRequest):
    # EXTRACCIÓN
    # La contraseña entra a memoria RAM aquí.
    pwd = input.password

    # SEGURIDAD: NO HACER LOGGING
    # Nunca escribir: print(pwd) ni logging.info(pwd)
    # Esto garantiza que la contraseña no quede en los registros del servidor.

    # PROCESAMIENTO (Llamadas a lógica matemática)
    try:
        L = len(pwd)
        N = logic.calculate_N(pwd)
        entropy = logic.calculate_entropy(pwd)
        crack_time = logic.estimate_crack_time(entropy)
        
        # Verificación en diccionario (O(1))
        is_breached = pwd in breached_db
        
        strength = logic.evaluate_strength(entropy, is_breached)

        # RETORNO
        # El objeto JSON se envía al cliente y la variable 'pwd' se destruye
        # automáticamente cuando la función termina (Garbage Collection).
        return EvaluationResponse(
            length_L=L,
            pool_size_N=N,
            entropy_bits=entropy,
            strength=strength,
            crack_time_estimate=crack_time,
            is_common_password=is_breached
        )
    except Exception as e:
        # En caso de error, nunca devolver la contraseña en el mensaje de error
        raise HTTPException(status_code=500, detail="Error interno al procesar la entropía.")