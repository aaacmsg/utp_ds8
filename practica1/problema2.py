# Control de dispositivos IoT
import random

temperatura = random.randint(15, 35)
humedad = random.randint(30, 70)
es_noche_hora = random.randint(0, 23)

if temperatura > 28:
    print("Activando ventilador...")

porcentaje_humedad = 40 / 100
calcular_porcentaje_humedad = humedad * porcentaje_humedad
if calcular_porcentaje_humedad < 40:
    print("Activando humidificador...")

if es_noche_hora > 18:
    print('Encender Luces...')

print('============================')
print('Estado de los dispositivos:')
print(f'Ventilador: {"Activado" if temperatura > 28 else "Desactivado"}')
print(f'Humidificador: {"Activado" if calcular_porcentaje_humedad < 40 else "Desactivado"}')
print(f'Luces: {"Activadas" if es_noche_hora > 18 else "Desactivadas"}')
print('============================')
