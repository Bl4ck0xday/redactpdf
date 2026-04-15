# RedactPDF

Convierte PDFs a imagen con texto invisible incrustado. Login seguro, solo usuarios autorizados.

---

## Estructura

```
redactpdf/
├── app.py
├── requirements.txt
├── render.yaml
├── users.json          ← se crea automáticamente
└── templates/
    ├── login.html
    └── tool.html
```

---

## Correr local

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Crear tu primer usuario
flask --app app create-user

# 3. Correr
python app.py
# Abre http://localhost:7860
```

---

## Deploy en Render.com (gratis)

1. Sube la carpeta a un repo en **GitHub** (puede ser privado)
2. Ve a https://render.com → New → Web Service
3. Conecta tu repo de GitHub
4. Render detecta el `render.yaml` automáticamente
5. Click **Deploy** — en 2-3 minutos tienes una URL pública

### Crear usuario en producción (Render)

En el dashboard de Render → tu servicio → **Shell**:
```bash
flask --app app create-user
```

---

## Seguridad implementada

- Contraseñas con hash PBKDF2-SHA256 (600,000 iteraciones)
- Sesiones firmadas con SECRET_KEY (auto-generada en deploy)
- SESSION_COOKIE_HTTPONLY — JavaScript no puede leer la cookie
- SESSION_COOKIE_SECURE — solo HTTPS en producción
- SESSION_COOKIE_SAMESITE=Lax — protección CSRF básica
- Todas las rutas de la herramienta requieren login
- Sesión expira en 8 horas
- Usuarios almacenados en users.json con hashes, nunca texto plano

---

## Agregar más usuarios

```bash
flask --app app create-user
```

Para eliminar un usuario, edita `users.json` manualmente y borra su entrada.
