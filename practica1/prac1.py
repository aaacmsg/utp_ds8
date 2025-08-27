temperatura = float(input("Ingrese la temperatura C°: "))

min_seguro = 18.0
max_seguro = 30.0

if temperatura >= min_seguro and temperatura <= max_seguro:
    print(f"{temperatura} la temperatura está en un rango seguro")
else:
    print(f"{temperatura} la temepratura no se encuentra en un rango seguro")