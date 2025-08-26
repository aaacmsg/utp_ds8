import datetime

# Lista para almacenar las lecturas de los sensores
lecturas_sensores = []

# Función para agregar una lectura
def agregar_lectura(valor, tipo_sensor):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lectura = (valor, timestamp, tipo_sensor)  # Tupla con la lectura
    lecturas_sensores.append(lectura)

# Función para calcular promedio de lecturas de temperatura
def promedio_temperatura():
    temperaturas = [lectura[0] for lectura in lecturas_sensores if lectura[2] == "temperatura"]
    if temperaturas:
        return sum(temperaturas) / len(temperaturas)
    else:
        return None

# Ejemplo de uso
agregar_lectura(25.3, "temperatura")
agregar_lectura(26.1, "temperatura")
agregar_lectura(23.8, "temperatura")
agregar_lectura(60, "humedad")
agregar_lectura(1013, "presion")

# Mostrar todas las lecturas
print("Lecturas registradas:")
for lectura in lecturas_sensores:
    print(lectura)

# Mostrar promedio de temperatura
promedio = promedio_temperatura()
if promedio is not None:
    print(f"\nPromedio de temperatura: {promedio:.2f} °C")
else:
    print("\nNo hay lecturas de temperatura registradas.")
