# Argon2

Verification helper for astro framework blog theme aria.

## TODO List / Pipeline

- [x] Vercel Firewall: filter requests with validate `X-Aria-Interaction-Auth` header
- [x] `POST` Only Function: `src/index.ts`
  - [x] Validate HMAC signature
  - [x] Load values from request body
  - [x] Run `argon2.verify()`
  - [x] Construct response json `{success, errcode}`
  - [x] Sign response with HMAC and return
