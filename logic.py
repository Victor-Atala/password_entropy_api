# logic.py
import math
import csv

# Alfabetos (Keyspace)
LOWERCASE = 26
UPPERCASE = 26
DIGITS = 10
SYMBOLS = 32

def calculate_N(password: str) -> int:
    pool_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if has_lower: pool_size += LOWERCASE
    if has_upper: pool_size += UPPERCASE
    if has_digit: pool_size += DIGITS
    if has_symbol: pool_size += SYMBOLS
    
    return pool_size

def calculate_entropy(password: str) -> float:
    L = len(password)
    N = calculate_N(password)
    if N == 0: return 0.0
    entropy = L * math.log2(N)
    return round(entropy, 2)

def estimate_crack_time(entropy: float) -> str:
    if entropy == 0: return "Instante"
    combinations = 2 ** entropy
    rate = 10**11 
    seconds = combinations / rate
    
    if seconds < 60: return f"{seconds:.4f} segundos"
    if seconds < 3600: return f"{seconds/60:.2f} minutos"
    if seconds < 86400: return f"{seconds/3600:.2f} horas"
    if seconds < 31536000: return f"{seconds/86400:.2f} días"
    if seconds < 3153600000: return f"{seconds/31536000:.2f} años"
    return "Siglos (Virtualmente imposible)"

def load_breached_passwords(filepath: str) -> set:
    breached_set = set()
    try:
        with open(filepath, mode='r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    breached_set.add(row[1].strip())
    except FileNotFoundError:
        print("ADVERTENCIA: Archivo passwords.csv no encontrado.")
    return breached_set

def evaluate_strength(entropy: float, is_breached: bool) -> str:
    if is_breached:
        return "Comprometida (En diccionario)"
    if entropy < 60:
        return "Débil / Aceptable"
    elif entropy < 80:
        return "Fuerte"
    else:
        return "Muy Fuerte"