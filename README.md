Cloudflare Pages + Functions + D1 demo template
--------------------------------------------------

Quick start:
1. Create a GitHub repo and push this project's files (all files and folders).
2. In Cloudflare dashboard:
   - Create a D1 database (e.g. MATCH_DB).
   - Go to D1 -> Run SQL -> paste schema.sql to create tables OR use wrangler d1 execute.
   - Deploy Pages: create a Pages project, link your GitHub repo, set root directory to 'public'.
   - In Pages project settings, under Functions, the 'functions' directory will be deployed as Pages Functions.
   - Bind D1 to Pages environment variable MATCH_DB (in Pages -> Settings -> Functions -> Add binding): name MATCH_DB, type D1, select your database.
   - Set environment variable JWT_SECRET to a secure value in Pages -> Settings -> Variables.
3. After deploy, visit the Pages URL. The front-end calls /api/* endpoints (Functions).

Notes:
- This is a demo prototype. Passwords are hashed with SHA-256 for simplicity; for production consider stronger practices.
- Token implementation is a simple HMAC-SHA256 based token for demo.
