# Módulos necesarios
import matplotlib.pyplot as plt                 # Crear gráficas
import os                                       # Acceder al sistema operativo

from collections import defaultdict             # Manejar colecciones de datos
from dotenv import load_dotenv                  # Cargar variables de entorno virtuali
from tenable.io import TenableIO                # Operar con el endpoint Tenable (API)


# Cargar variables del entorno virtual '.env'
load_dotenv()

ACCESS_KEY = os.getenv('ACCESS')
SECRET_KEY = os.getenv('SECRET')


def top_n(scan_id: int, n: int):
    """
    Muestra por pantalla el Top N de 'plugin_family' en función de
    la cantidad de vulnerabilidades.
    
    :param scan_id:    El ID del escaneo del que procesar las vulnerabilidades.
    :param n:          El número del top que se quiere generar.
    """
    # Extraer las vulnerabilidades del resultado del escaneo (por defecto: '[]')
    vulns = tenable.scans.results(scan_id).get('vulnerabilities', [])
    
    # Filtrar las vulnerabilidades con 'severity' de 1 o más
    filtered = [ v for v in vulns if 1.0 <= v.get('severity', 0) ]

    groups = defaultdict(int)

    # Contar las vulnerabilidades por el campo 'plugin_family'
    for vuln in filtered:
        family = vuln.get('plugin_family', '-')     # (por defecto: '-')
        count = vuln.get('count', 0)                # (por defecto: '0')

        groups[family] += count

    # Ordenar y obtener el Top N de 'plugin_family' con más vulnerabilidades
    top = sorted(groups.items(), key=lambda x: x[1], reverse=True)[:n]
    
    print(f"\n\tTop {n} según 'plugin_family':\n")
    
    for i, (family, total) in enumerate(top, 1):
        print(f'\t{i}. {family}: {total} vulnerabilidades')


def pie_chart(scan_id: int) -> str:
    """
    Genera la imagen de un gráfico de vulnerabilidades cateforizadas por
    severidad y muestra por pantalla los datos del gráfico.
    
    El gráfico no muestra las categorías con 0 vulnerabilidades.
    
    :param scan_id:    El ID del escaneo del que procesar las vulnerabilidades.
    
    :return:    La ruta de la imagen generada (fichero), o '' si hubo un error.
    """
    try:
        # Extraer las vulnerabilidades del resultado del escaneo (por defecto: '[]')
        vulns = tenable.scans.results(scan_id).get('vulnerabilities', [])
        
        # Categorías (severidad)
        categories = {'Crítica': 0, 'Alta': 0, 'Media': 0, 'Baja': 0}
        
        # Contar las vulnerabilidades por categoría    
        for v in vulns:
            count = v.get('count', 0)
            severity = v.get('severity', 0)
            
            if 9.0 <= severity <= 10.0: categories['Crítica'] += count
            elif 7.0 <= severity < 9.0: categories['Alta'] += count
            elif 4.0 <= severity < 7.0: categories['Media'] += count
            elif 0.1 <= severity < 4.0: categories['Baja'] += count
        
        print('\n\tCategorías de vulnerabilidades:\n')
        
        for cat, cnt in categories.items():
            print(f'\t{cat}: {cnt}')
        
        # Eliminar las categorías sin vulnerabilidades (mayor legibilidad)
        filtered = {k: v for k, v in categories.items() if 0 < v}
        
        if not filtered:
            print('\n\tNo hay suficientes datos para generar el gráfico.')
            return ''
        
        labels = list(filtered.keys())
        sizes = list(filtered.values())
        
        # Configuración del gráfico
        plt.figure(figsize=(6, 6))
        plt.title(f'Escaneo #{scan_id}: vulnerabilidades categorizadas')
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=0)
        plt.axis('equal')
        # plt.show()
        
        # Ruta del fichero
        path = os.path.join(os.getcwd(), f'{scan_id}_categorized.png')
        
        # Guardar la imagen
        plt.savefig(path)
        plt.close()
        
        print(f"\n\tGráfico guardado en '{path}'.")
        return path
    
    except Exception as e:
        print(f'Error al general el gráfico: "{e}".')
        return ''


if __name__ == '__main__':
    # Instanciar el acceso a Tenable
    tenable = TenableIO(access_key=ACCESS_KEY, secret_key=SECRET_KEY)

    # Iterar sobre todos los escaneos a los que se tiene acceso
    for scan in tenable.scans.list():   # TODO: tarea 1/3
        scan_id = scan["id"]

        print(f'#{scan_id}: "{scan["name"]}"')
        
        top_n(scan_id, 5)   # TODO: tarea 2/3
        pie_chart(scan_id)  # TODO: tarea 3/3
