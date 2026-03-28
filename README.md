# api-auth

API REST de ejemplo para autenticación basada en JWT y bcrypt.

## Descripción
Servicio Express que gestiona usuarios y autenticación mediante tokens JWT. Usa HTTPS con certificados locales y MongoDB (via `mongojs`).

Código principal: [index.js](index.js)  
Configuración: [`config.js`](config.js)

## Características
- Registro de usuario y login con password hasheada (`bcrypt`).
  - Hash: [`PasswordHelper.encriptaPassword`](helpers/pass.helper.js)
  - Comparación: [`PasswordHelper.comparaPassword`](helpers/pass.helper.js)
- Emisión y verificación de tokens JWT:
  - Crear token: [`TokenHelper.creaToken`](helpers/token.helper.js)
  - Decodificar token: [`TokenHelper.decodificaToken`](helpers/token.helper.js)
- Middleware de autenticación: [`AuthMiddleware.auth`](middlewares/auth.middleware.js)
- Servido sobre HTTPS usando:
  - Certificado: [cert/cert.pem](cert/cert.pem)
  - Clave privada: [cert/key.pem](cert/key.pem)

## Requisitos
- Node.js (v14+ recomendado)
- MongoDB accesible (local o remoto)

La cadena de conexión se toma de [`config.js`](config.js) (propiedad `DB`).

## Instalación
```sh
npm install
```

## Uso
Iniciar servidor en modo desarrollo:
```sh
npm start
```
El servidor escucha en `https://localhost:<PORT>` (ver [`config.js`](config.js) para `PORT`).

## Endpoints principales
- GET /api/user — Lista usuarios (requiere token). Protegido por [`AuthMiddleware.auth`](middlewares/auth.middleware.js)
- GET /api/user/:id — Obtiene usuario por id (requiere token)
- POST /api/user — Crea usuario (requiere token)
- PUT /api/user/:id — Actualiza usuario (requiere token)
- DELETE /api/user/:id — Elimina usuario (requiere token)

Rutas de autenticación:
- POST /api/auth/reg — Registro público. Body:
  ```json
  { "displayName": "Nombre", "email": "a@b.com", "password": "secreto" }
  ```
  Genera token con [`TokenHelper.creaToken`](helpers/token.helper.js)

- POST /api/auth/login — Login público. Body:
  ```json
  { "email": "a@b.com", "password": "secreto" }
  ```
  Devuelve token si credenciales válidas.

- GET /api/auth/me — Información del usuario asociado al token (requiere token)
- GET /api/auth — Lista (solo email y displayName) (requiere token)

## Autenticación
Enviar header:
```
Authorization: Bearer <jwtToken>
```
La verificación la realiza [`AuthMiddleware.auth`](middlewares/auth.middleware.js) usando [`TokenHelper.decodificaToken`](helpers/token.helper.js).

## Archivos relevantes
- [index.js](index.js)
- [config.js](config.js)
- [package.json](package.json)
- [`helpers/token.helper.js`](helpers/token.helper.js) — funciones JWT
- [`helpers/pass.helper.js`](helpers/pass.helper.js) — bcrypt
- [`middlewares/auth.middleware.js`](middlewares/auth.middleware.js) — middleware auth
- [cert/cert.pem](cert/cert.pem)
- [cert/key.pem](cert/key.pem)

## Notas
- El secreto del token y tiempo de expiración están en [`config.js`](config.js) (`SECRET`, `TOKEN_EXP_TIME`).
- El servidor se ejecuta sobre HTTPS con los archivos de `cert/`.
- Ajustar CORS y cabeceras según necesidades de producción