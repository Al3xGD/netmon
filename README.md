# NetMon — Monitor de Conexiones de Red en Tiempo Real

Aplicación de escritorio con ImGui que muestra todas las conexiones TCP/UDP activas
del sistema: entrantes, salientes y en escucha, con actualización automática.

## Características
- Vista en tiempo real de conexiones TCP, TCP6 y UDP
- Tabs separados: Todas / Entrantes (LISTEN) / Salientes (ESTABLISHED)
- Sparklines de historial (últimas 60 muestras)
- Filtro por texto (IP, puerto, proceso)
- Filtro por protocolo y estado
- Detección de nombre de proceso por PID
- Velocidad de actualización configurable (500ms–5s)
- Tema oscuro profesional

## Requisitos

### Ubuntu / Debian
```bash
sudo apt install build-essential libsdl2-dev libgl1-mesa-dev libglew-dev git
```

### Arch Linux
```bash
sudo pacman -S sdl2 glew mesa git base-devel
```

### Fedora
```bash
sudo dnf install gcc-c++ SDL2-devel mesa-libGL-devel glew-devel git
```

## Compilar y ejecutar

```bash
# Clonar ImGui
git clone --depth=1 https://github.com/ocornut/imgui.git

# Compilar
make

# Ejecutar (requiere permisos para leer /proc)
./netmon
# Si no ve los procesos, ejecutar con sudo:
sudo ./netmon
```

## Atajos
- **Filtro**: escribir en la caja de texto filtra IP, puerto y nombre de proceso
- **Refresh slider**: ajusta la velocidad de actualización
- **Checkboxes**: activa/desactiva protocolos TCP/TCP6/UDP
- **Combo Estado**: filtra por estado de conexión

## Notas de seguridad
El programa solo lee `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp` y `/proc/[pid]/fd/`.
No realiza ninguna conexión de red ni modifica el sistema.
