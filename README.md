# Argon2

Verification helper for astro framework blog theme aria.

## TODO List / Pipeline

- [ ] Vercel Firewall: filter requests with validate `X-Aria-Interaction-Auth` header
  - [ ] Edit desired `X-Aria-Interaction-Auth` value
- [ ] `POST` Only Function: `src/index.ts`
  - [ ] Validate HMAC signature
  - [ ] Load values from request body
  - [ ] Run `argon2.verify()`
  - [ ] Construct response json `{success, errcode}`
  - [ ] Sign response with HMAC and return
