# Panorama global de ciberataques y vulnerabilidades (2015-2025)

Visualización interactiva del panorama global de ciberseguridad en la última década, desarrollada como caso práctico de la asignatura **Visualización de Datos** del Máster en Ingeniería y Ciencia de Datos (UNED).

**Autora:** Olaya Folgueiras González

El proyecto integra siete fuentes de datos abiertas en un pipeline reproducible y responde, mediante doce visualizaciones construidas con **Altair** e integradas en un dashboard **Streamlit**, a preguntas como cómo evolucionan el volumen y la gravedad de las vulnerabilidades, qué sectores sufre cada tipo de ataque, si lo más grave coincide con lo más explotado, y cuál es el impacto del cibercrimen en usuarios y economía.

| Fuente                                                                   | Contenido                                      | Registros usados |
| ------------------------------------------------------------------------ | ---------------------------------------------- | ---------------- |
| [NVD/NIST](https://nvd.nist.gov/)                                        | Vulnerabilidades CVE con CVSS, severidad y CWE | 241.888          |
| [VCDB](https://github.com/vz-risk/VCDB)                                  | Incidentes reales (estándar VERIS)             | 4.356            |
| [EuRepoC](https://eurepoc.eu/)                                           | Incidentes con atribución e intensidad         | 2.651            |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs con explotación confirmada                | 1.395            |
| [EPSS (FIRST.org)](https://www.first.org/epss/)                          | Probabilidad de explotación por CVE            | 241.888          |
| [Have I Been Pwned](https://haveibeenpwned.com/)                         | Brechas y cuentas comprometidas                | 797              |
| [Ransomwhere](https://ransomwhe.re/)                                     | Pagos de ransomware verificados                | 20.939           |

## Contenido del repositorio

| Ruta                       | Qué es                                                    |
| -------------------------- | --------------------------------------------------------- |
| `app/app.py`               | Dashboard Streamlit, la visualización final                 |
| `src/`                     | Pipeline completo: adquisición, preprocesado y visualización |
| `data/processed/`          | Los cinco datasets analíticos en Parquet, listos para usar   |
| `data/external/`           | Geometrías de países y tabla ISO 3166                        |
| `notebooks/`               | Análisis exploratorio con las figuras y su trazabilidad      |
| `Makefile`                 | Todos los comandos del proyecto                              |

**No se incluye `data/raw/`**, unos 145 MB de descargas originales. No hace falta para ejecutar nada, porque los datos procesados vienen incluidos, y se regenera con los comandos de la sección [Datos](#datos).

El razonamiento de diseño y de análisis está en el notebook de EDA, junto a cada gráfico; este fichero solo cubre cómo ejecutar el proyecto.

## Estructura del repositorio

```
ciberataques/
├── app/                # dashboard Streamlit (la visualización final)
├── data/
│   ├── raw/            # descargas por fuente (se regeneran, no versionadas)
│   ├── processed/      # datasets analíticos en Parquet (incluidos en el repo)
│   └── external/       # geometrías de países y códigos ISO 3166
├── notebooks/          # EDA con las figuras y sus justificaciones de diseño
├── src/
│   ├── acquisition/    # un cliente de descarga por fuente + CLI
│   ├── preprocessing/  # limpieza, taxonomías comunes e integración
│   ├── visualization/  # tema, constructores Altair y dashboard enlazado
│   └── utils/          # rutas y E/S
├── Makefile            # todos los comandos del proyecto
└── requirements.txt
```

## Requisitos e instalación

Python 3.10 o superior.

```bash
pip install -r requirements.txt
```

## Ejecutar el dashboard

Los datos procesados están incluidos en el repositorio, de modo que el dashboard funciona nada más clonar e instalar dependencias.

```bash
make app          # equivale a: streamlit run app/app.py
```

Se abre en `http://localhost:8501`, con filtros globales (periodo, severidad, fuente, sector), indicadores con comparativa temporal y vistas enlazadas (brushing & linking). Arranca en tema oscuro; el menú de ajustes de la propia aplicación permite pasar a claro, y la paleta de los gráficos sigue a la variante activa.

## Datos

### Datos procesados (incluidos)

`data/processed/` contiene los cinco datasets analíticos en Parquet (vulnerabilidades enriquecidas con KEV y EPSS, incidentes unificados, brechas, pagos de ransomware y el agregado mensual). Son el resultado del pipeline descrito abajo y bastan para ejecutar el dashboard y el notebook.

### Regenerar el pipeline desde las fuentes originales (opcional)

No hace falta para nada de lo anterior: los datos procesados vienen incluidos. Estos son los comandos si se quiere rehacer la cadena entera desde el crudo. La descarga es reproducible y no necesita claves de API; cada fuente deja un `manifest.json` con la URL, la fecha y el número de registros obtenidos.

```bash
# 1 · Descarga del crudo a data/raw/ (~145 MB, 30-45 min en total)
make data-all                    # las siete fuentes de una vez

# o fuente a fuente, si se prefiere ir por partes:
make data-kev data-epss data-hibp data-ransomwhere   # ligeras, segundos
make data-eurepoc                                    # ~25 MB desde Zenodo
make data-vcdb                                       # ~100 MB desde GitHub
make data-nvd                                        # API oficial, 25-40 min

make data-verify                 # volúmenes y cobertura de lo descargado

# 2 · Preprocesado e integración, de data/raw/ a data/processed/
make preprocess                  # ~2 min
make preprocess-verify           # comprueba el resultado

# 3 · Regenerar los artefactos derivados
make figures                     # las quince figuras PNG a figures/
```

La descarga de NVD respeta los límites de su API pública, con ventanas de 120 días y persistencia incremental, así que si se interrumpe continúa donde quedó al relanzarla.

Las decisiones de limpieza, filtrado y taxonomías comunes se argumentan en la sección 1 del notebook de EDA, y las asignaciones concretas viven en `src/preprocessing/taxonomies.py`.

## Otros comandos

| Comando                                        | Descripción                                       |
| ---------------------------------------------- | ------------------------------------------------- |
| `make app`                                     | Lanza el dashboard Streamlit                      |
| `make figures`                                 | Exporta las figuras PNG a `figures/`              |
| `make palette`                                 | Verifica la separación perceptiva de la paleta    |
| `make data-all`                                | Descarga las siete fuentes                        |
| `make preprocess`                              | Ejecuta el pipeline de limpieza e integración     |
| `jupyter lab notebooks/eda_ciberataques.ipynb` | Abre el EDA con las figuras y sus justificaciones |

## Diseño

El sistema visual parte de una paleta única de familia índigo, definida en `src/visualization/theme.py` y compartida por el cuaderno, la app y las figuras exportadas. Una rampa secuencial de un solo tono codifica volumen y actividad, un gradiente de cuatro pasos que vira al cálido codifica la severidad ordinal, el acento cálido se reserva a la explotación confirmada y el tono solo se usa en variables nominales, mediante una paleta cualitativa derivada de la de Okabe e Ito, diseñada para dicromatopsias. `make palette` mide banda de luminosidad, croma, contraste y separación CIEDE2000 bajo protanopía, deuteranopía y tritanopía, e imprime la paleta de referencia junto a las del proyecto. La justificación de diseño de cada figura, y la de la composición del dashboard, está en el notebook de EDA junto a cada gráfico.

## Limitaciones de los datos

VCDB tiene sesgo de reporte estadounidense y decae tras 2020; EuRepoC cubre hasta diciembre de 2024; el catálogo KEV existe desde finales de 2021; EPSS es una instantánea actual, no una serie histórica; el sector de HIBP se infiere del texto. Las comparaciones entre países reflejan actividad documentada, no incidencia real.
