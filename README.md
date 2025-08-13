# DAST POC App - Aplicación FastAPI Vulnerable

> ⚠️ **ADVERTENCIA**: Esta aplicación contiene vulnerabilidades intencionales para pruebas de seguridad. NO usar en entornos de producción.

## Descripción

Esta es una aplicación de demostración desarrollada con FastAPI que contiene vulnerabilidades intencionales para pruebas de Dynamic Application Security Testing (DAST). La aplicación implementa un sistema básico de autenticación con JWT y almacenamiento en SQLite.

## Vulnerabilidades implementadas

- **SQL Injection**: El endpoint `/users/search` utiliza una consulta SQL vulnerable que permite inyección.
  - Ejemplo de explotación: `?username=a'%20OR%201=1%20--%20`

- **Cross-Site Scripting (XSS)**: El endpoint `/render` muestra contenido HTML sin sanitizar.
  - Ejemplo de explotación: `?content=<script>alert('XSS')</script>`

- **Path Traversal**: El endpoint `/files/{file_path}` permite acceder a archivos fuera del directorio permitido.
  - Ejemplo de explotación: `/files/../../../etc/passwd`

- **Configuración insegura de CORS**: Configurado para permitir cualquier origen (`*`).

- **Headers de seguridad insuficientes**: Faltan headers importantes como Content-Security-Policy.

- **Secretos hardcodeados**: Clave JWT predeterminada en el código si no se configura en variables de entorno.

## Requisitos

- Python 3.8+
- uv (gestor de paquetes y entorno virtual)

## Instalación

1. Clona este repositorio
2. Instala las dependencias:

```bash
uv sync
```

## Configuración del entorno

Crea un archivo `.env` basado en `env.example` con las siguientes variables:

```
JWT_SECRET=tu_clave_secreta
JWT_ALG=HS256
JWT_EXPIRE_MINUTES=120
DATABASE_URL=sqlite:///./app.db
```
## Ejecución

Para ejecutar la aplicación en modo desarrollo:

```bash
uv run uvicorn app.main:app --reload
```

La aplicación estará disponible en: http://localhost:8000

## Documentación API

La documentación interactiva de la API estará disponible en:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Endpoints principales

- `/auth/login` - Autenticación de usuarios (POST)
- `/users` - Listar todos los usuarios (GET)
- `/users/search` - Buscar usuarios (GET, vulnerable a SQL Injection)
- `/me` - Información del usuario actual (GET, requiere autenticación)
- `/notes` - Gestión de notas (GET, POST, requiere autenticación)

## Credenciales de prueba

- Usuario: `alice`, Contraseña: `password123`
- Usuario: `bob`, Contraseña: `hunter2`

## Notas de seguridad

Esta aplicación contiene vulnerabilidades intencionales para fines educativos y de prueba. No debe utilizarse en entornos de producción ni exponerse públicamente.