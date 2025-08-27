import statistics
from datetime import datetime

# Lecturas de sensores IoT (temperatura °C, humedad %, fecha, hora)
# Formato: (temperatura, humedad, fecha, hora)
lecturas_sensores = [
    (25.3, 55, "2025-08-25", "10:00"),
    (26.1, 58, "2025-08-25", "11:00"),
    (24.8, 53, "2025-08-25", "12:00"),
    (100.0, 10, "2025-08-25", "13:00"),  # Valor atípico
    (25.7, 54, "2025-08-25", "14:00"),
    (26.4, 57, "2025-08-25", "15:00")
]

# --- Funciones de análisis ---

def calcular_estadisticas(valores):
    return {
        "máximo": max(valores),
        "mínimo": min(valores),
        "promedio": statistics.mean(valores)
    }

def detectar_atipicos(valores):
    media = statistics.mean(valores)
    desviacion = statistics.pstdev(valores)  # desviación estándar poblacional
    atipicos = [v for v in valores if abs(v - media) > 2 * desviacion]
    return atipicos

# --- Procesamiento de datos ---
temperaturas = [t[0] for t in lecturas_sensores]
humedades = [t[1] for t in lecturas_sensores]

# Estadísticas
estad_temp = calcular_estadisticas(temperaturas)
estad_hum = calcular_estadisticas(humedades)

# Atípicos
outliers_temp = detectar_atipicos(temperaturas)
outliers_hum = detectar_atipicos(humedades)

# --- Resultados ---
print("📊 Estadísticas de Temperatura:", estad_temp)
print("📊 Estadísticas de Humedad:", estad_hum)

print("⚠️ Valores atípicos en Temperatura:", outliers_temp if outliers_temp else "Ninguno")
print("⚠️ Valores atípicos en Humedad:", outliers_hum if outliers_hum else "Ninguno")
