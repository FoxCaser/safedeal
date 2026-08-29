# SafeDeal v7.0 Launch Candidate

Consolidated build with seller/job/link/Telegram/phone/text checks, browser OCR, PostgreSQL history/accounts, moderated complaints, appeals, admin moderation, password reset, and production hardening.

## Deploy
Replace/upload these files to the repository and deploy the latest commit on Render.

Required environment variables: `DATABASE_URL`, `ADMIN_KEY`. Set `APP_BASE_URL` to the final public URL. External provider keys are optional but improve coverage.

For password reset to arbitrary recipients, `RESEND_FROM` must use a domain verified in Resend. Until that is done, Resend testing restrictions still apply.

`SHOW_DEMO_DATA` should stay `false` in production.

## Important
No automated anti-fraud system can guarantee that a person or deal is safe or fraudulent. SafeDeal exposes risk signals and moderated community reports, with an appeal workflow.


## v7.1 Premium Design
- Перенесено преміальний темно-синій/фіолетовий дизайн на реальний SafeDeal.
- Backend, API, IDs елементів, app.js, акаунти, історія, скарги та адмінка не змінювались.
- OLX та Instagram у промо-блоці позначені «СКОРО», щоб не заявляти функції до їх реалізації.
