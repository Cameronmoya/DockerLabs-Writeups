[README.md](https://github.com/user-attachments/files/33845583/README.md)
# Reporte de Auditoría de Seguridad — Laboratorio TRON

**Objetivo:** `http://172.17.0.2/` (contenedor DockerLabs, red local de laboratorio)
**Fecha:** 22 de octubre de 2026
**Tipo de prueba:** Auditoría de seguridad / hacking ético con autorización sobre entorno de laboratorio
**Resultado global:** **CRÍTICO — compromiso total del sistema (root)**
**Flag obtenida:** `DL{disco}`

---

## 1. Resumen ejecutivo

La auditoría se realizó sobre la máquina virtual de laboratorio TRON, accesible en la red Docker local (`172.17.0.2`). El sistema exponía únicamente dos servicios: **SSH (22/tcp)** y **HTTP (80/tcp)**. La página web aparentaba ser un sitio estático sin funcionalidad, lo que reducía la superficie de ataque visible.

Aun así, se identificó una cadena de compromiso completa en cuatro fases:

1. **Esteganografía en la imagen pública** `tron.jpg`: contenía un mensaje oculto protegido con contraseña vacía.
2. **Credenciales SSH débiles**: el usuario `tron` utilizaba la contraseña `tron`.
3. **Escalada de privilegios**: la regla `tron ALL=(ALL) NOPASSWD: /usr/bin/env` permitió ejecutar una shell como `root` sin contraseña.
4. **Acceso a información sensible**: se leyó `/root/sistema.txt` y se ejecutó el binario `/root/login_flynn`, obteniendo la flag `DL{disco}`.

El impacto es máximo: un atacante con acceso a la red del laboratorio pudo obtener **ejecución de comandos remota** primero como usuario sin privilegios y después como **root**, tomando control total del contenedor. Aunque se trata de un entorno formativo, los mismos patrones (secretos ocultos en recursos públicos, credenciales por defecto y reglas `sudo` peligrosas) son habituales en entornos reales y deben corregirse.

**Nivel de riesgo: Crítico (9,8/10)**

---

## 2. Alcance y metodología

- **Alcance:** host `172.17.0.2`, puertos TCP 22 y 80, aplicación web y configuración del sistema operativo del contenedor.
- **Metodología:** reconocimiento, enumeración de servicios y contenido web, análisis de artefactos públicos, obtención de credenciales, acceso inicial, escalada de privilegios y recolección de evidencia (alineado con PTES y MITRE ATT&CK).
- **Herramientas utilizadas:** `nmap`, `gobuster`, `ffuf`, `curl`, `steghide`, `exiftool`, `paramiko` (cliente SSH), utilidades GNU/Linux.
- **Autorización:** prueba ejecutada sobre una máquina de laboratorio DockerLabs desplegada localmente, sin afectación a sistemas de terceros.

---

## 3. Superficie de ataque

| Puerto | Servicio | Versión identificada |
|--------|----------|----------------------|
| 22/tcp | SSH | OpenSSH 10.2p1 Ubuntu-2ubuntu3.8 |
| 80/tcp | HTTP | Apache httpd 2.4.66 (Ubuntu) |

Sistema operativo: **Ubuntu 26.04.1 LTS**.  
Sudo: **1.9.17p2**.  
La enumeración web con diccionarios (`common.txt`, `raft-medium-directories.txt`, `big.txt`, extensiones `php/html/txt/bak/zip`) no reveló paneles, CMS ni rutas dinámicas: únicamente `index.html`, `tron.jpg` y `server-status` (403).

---

## 4. Hallazgos

### H-01 — Información oculta en imagen pública (esteganografía) — Riesgo MEDIO

La imagen publicada en la web (`/tron.jpg`) contenía un archivo embebido mediante `steghide` protegido con **contraseña vacía**:

```bash
steghide extract -sf tron.jpg -p "" -xf disco.txt
cat disco.txt
```

Contenido extraído:

```
quorra
"Lo que pasa con la perfección es que es incognoscible. Es imposible,
pero también está justo frente a nosotros todo el tiempo."
```

**Impacto:** filtración de una palabra clave (`quorra`) que resultó ser credencial del binario sensible `/root/login_flynn`. Cualquier visitante podía descargar la imagen y extraerla.

**Recomendación:** no almacenar secretos en recursos públicos ni confiar en esteganografía como control de seguridad. Rotar cualquier credencial que haya estado embebida y eliminar los artefactos afectados.

---

### H-02 — Credenciales SSH débiles / contraseña por defecto — Riesgo CRÍTICO

El servicio SSH aceptaba autenticación por contraseña y el usuario `tron` tenía la contraseña `tron`:

```text
tron@172.17.0.2's password: tron

uid=1001(tron) gid=1001(tron) groups=1001(tron)
```

**Impacto:** acceso inicial al sistema con una credencial trivialmente adivinable. Un ataque de diccionario o de pulverización de contraseñas compromete el host en segundos. SSH permitía autenticación por contraseña (no se restringió a claves).

**Recomendación:**

- Eliminar cuentas y contraseñas por defecto.
- Aplicar una política de contraseñas robusta y bloqueo por intentos fallidos.
- Deshabilitar `PasswordAuthentication` y usar exclusivamente claves SSH.
- Restringir SSH por red de gestión / VPN y aplicar fail2ban.

---

### H-03 — Escalada de privilegios mediante `sudo` con `env` — Riesgo CRÍTICO

La configuración de sudo contenía:

```text
tron ALL=(ALL) NOPASSWD: /usr/bin/env
```

`env` permite ejecutar un intérprete arbitrario, por lo que la restricción es ficticia:

```bash
sudo -n /usr/bin/env /bin/bash -c 'id; whoami'
uid=0(root) gid=0(root) groups=0(root)
root
```

**Impacto:** escalada inmediata de `tron` a **root** sin contraseña. Técnica equivalente a GTFOBins (`env` → shell).

**Recomendación:**

- Eliminar la regla y cualquier permiso `NOPASSWD` sobre intérpretes o binarios que permitan ejecutar comandos (`env`, `bash`, `python`, `find`, `awk`, `vim`, etc.).
- Si se necesita delegar una tarea, usar un script con argumentos fijos y propietario `root`, sin posibilidad de inyección.
- Auditar `/etc/sudoers` y `/etc/sudoers.d/*` periódicamente.

---

### H-04 — Exposición de versiones y falta de endurecimiento — Riesgo BAJO/MEDIO

- El servidor HTTP revela versión y sistema operativo: `Server: Apache/2.4.66 (Ubuntu)`.
- El sitio no utiliza HTTPS ni cabeceras de seguridad (`HSTS`, `CSP`, `X-Frame-Options`, etc.).
- SSH mantiene autenticación por contraseña habilitada.
- No se observan controles de detección/bloqueo ante intentos de autenticación.

**Recomendación:** ocultar banners (`ServerTokens Prod`, `ServerSignature Off`), forzar TLS, añadir cabeceras de seguridad, deshabilitar autenticación por contraseña en SSH y desplegar monitorización/alertas.

---

### H-05 — Credenciales y flag embebidas en binario de root — Riesgo MEDIO

El binario `/root/login_flynn` contenía la contraseña `quorra` y la flag en texto claro, además de un mensaje provocador en `/root/sistema.txt`. Una vez obtenido root, fue posible ejecutarlo y extraer la flag:

```text
Username: quorra
Password: quorra

[+] ¡Felicidades! Has ganado.
Flag: DL{disco}
```

**Recomendación:** no incrustar secretos en binarios ni en cadenas de texto; usar gestores de secretos y permisos mínimos. En un entorno real, rotar inmediatamente las credenciales expuestas.

---

## 5. Cadena de ataque (kill chain)

| Fase | Acción | Resultado |
|------|--------|-----------|
| Reconocimiento | `nmap -sT -Pn -p- 172.17.0.2` | Puertos 22/80 abiertos |
| Enumeración web | `gobuster` / `ffuf` / `curl` | Sitio estático, imagen `tron.jpg` |
| Análisis de artefactos | `steghide extract -p ""` | Credencial `quorra` |
| Acceso inicial | SSH `tron:tron` | Shell como `tron` (RCE) |
| Escalada | `sudo /usr/bin/env /bin/bash` | Shell como `root` |
| Post-explotación | Lectura de `/root`, ejecución de `login_flynn` | Flag `DL{disco}` |

**Evidencia de ejecución remota de comandos:**

```bash
$ ssh tron@172.17.0.2
tron@172.17.0.2's password: tron
$ id
uid=1001(tron) gid=1001(tron) groups=1001(tron)
$ sudo -n /usr/bin/env /bin/bash -c 'id'
uid=0(root) gid=0(root) groups=0(root)
```

---

## 6. Recomendaciones priorizadas

1. **Inmediata:** eliminar la regla `NOPASSWD` sobre `/usr/bin/env` y revisar todo `/etc/sudoers`.
2. **Inmediata:** cambiar la contraseña de `tron` y deshabilitar la autenticación por contraseña en SSH.
3. **Alta:** eliminar secretos de imágenes y binarios públicos; rotar `quorra` y cualquier credencial asociada.
4. **Media:** forzar HTTPS y añadir cabeceras de seguridad; ocultar versiones de servidor.
5. **Media:** implantar monitorización, bloqueo por intentos fallidos y principio de mínimo privilegio.
6. **Continua:** revisiones de configuración (CIS Benchmarks), análisis de secretos en repositorios/artefactos y pruebas de escalada de privilegios periódicas.

---

## 7. Conclusión

El laboratorio TRON es comprometible de principio a fin con técnicas básicas y sin necesidad de exploits de memoria. La combinación de **secretos ocultos en una imagen pública**, **credenciales por defecto** y una **regla sudo mal configurada** permite a un atacante pasar de un simple visitante web a **root** en pocos minutos, con acceso total a la información del sistema.

La corrección de los puntos 1 y 2 del apartado de recomendaciones elimina la práctica totalidad de la cadena de ataque.

---

### Anexo — Evidencia clave

- Puerto 80: `Apache/2.4.66 (Ubuntu)`, título `TRON`, contenido estático.
- Imagen: `http://172.17.0.2/tron.jpg` (29.698 bytes) con datos embebidos extraíbles sin contraseña.
- SSH: `OpenSSH 10.2p1`, login válido `tron:tron`.
- Sudo: `tron ALL=(ALL) NOPASSWD: /usr/bin/env`.
- Flag final: `DL{disco}`.
