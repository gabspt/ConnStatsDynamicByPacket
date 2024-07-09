## sumar todos los numeros de las columna 3 + todos los numeros de la columna 5 y darme el resultado final
import csv
#import sys

def count(file):
    with open(file, 'r') as f:
        reader = csv.reader(f)
        next(reader)
        suma = 0
        for row in reader:
            suma += int(row[3]) + int(row[5])
        return suma
    
if __name__ == '__main__':
    file = "t.csv"
    print(count(file))
