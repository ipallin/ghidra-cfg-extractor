# ghidra-cfg-extractor

Herramientas para extraer grafos de flujo de control (CFG) de binarios compilados
utilizando Ghidra en modo *headless*.

## Requisitos

- [Ghidra](https://ghidra-sre.org/) instalado localmente. Puedes indicar la
  ubicación mediante la variable de entorno `GHIDRA_INSTALL_DIR` o con el
  argumento `--ghidra-install` del script.
- Python 3.9 o superior para ejecutar el script `extract_cfg.py`.

## Uso

```bash
python extract_cfg.py --ghidra-install /ruta/a/ghidra \
  --output-dir cfgs \
  /ruta/al/binario1 /ruta/al/binario2
```

Para cada binario analizado se generará un archivo `*.cfg.<formato>` en el
directorio indicado con `--output-dir`. El contenido incluye la información
básica del programa junto con las listas de bloques y aristas del CFG de cada
función. El formato por defecto es JSON, pero también se puede exportar a
GraphML.

### Opciones destacadas

- `--keep-project`: conserva el proyecto temporal de Ghidra creado durante el
  análisis.
- `--overwrite`: permite sobreescribir archivos de salida existentes.
- `--script`: ruta personalizada a un *post-script* de Ghidra. Por defecto se
  utiliza `ghidra_scripts/export_cfg.py` incluido en este repositorio.
- `--language-id`: fuerza el *language*/*processor* de Ghidra (por ejemplo,
  `x86:LE:32:default`) cuando la detección automática no funciona.
- `--format`: elige el formato de salida (`json` o `graphml`).

## Script de Ghidra

El archivo `ghidra_scripts/export_cfg.py` es un script de Ghidra (Jython) que se
encarga de recorrer todas las funciones del binario y generar el grafo de flujo
de control. Actualmente admite los formatos JSON y GraphML y se ejecuta
automáticamente mediante la opción `-postScript` del comando
`analyzeHeadless` de Ghidra.
