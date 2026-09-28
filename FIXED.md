# Fixed — nextendo-nnaccount-nx

- **Sign-in "server error"**: `users/me` in production's full shape; `iconUri` served; `session_token` in the code grant.
- **Linking/import found no user**: every id_token carries `nintendo.ai` (the Nextendo account's BaaS user).
- **"Sign in to your Nintendo Account again" (D3)**: a Nintendo Account linked on production gets its own local account
  (`NNACCOUNT_LOCAL_OPEN=1`) instead of being refused.
- **Page opening from the account applet spun forever**: silent authorize (`prompt=none`) answers the OAuth redirect.
- **Secrets in the log**: authorization codes, code verifiers and session tokens are masked like passwords.

## Credits

- [kinnay/NintendoClients wiki](https://github.com/kinnay/NintendoClients/wiki) — account server and client ids.
- The whole Nextendo Network team — https://nextendo.network. Nextendo is awesome.
