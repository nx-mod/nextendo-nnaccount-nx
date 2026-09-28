# nextendo-nnaccount-nx

The Nintendo Account side of a local Nextendo stack: `accounts.nintendo.com` `/connect` (tokens, the account-link page, authorize), `/1.0.0/certificates` and `api.accounts.nintendo.com` `/2.0.0/users/me`, for the accounts `nextendo-account` holds. Production Nextendo serves these from a private service; this is nx-mod's rewrite, so a LAN stack sends nothing upstream. Plain HTTP behind [nextendo-tls-front](https://github.com/nx-mod/nextendo-tls-front). Part of [nextendo-testing](https://github.com/nx-mod/nextendo-testing).

- The account-link page signs in with a Nextendo e-mail and password (a new e-mail creates the account with nextendo-account's local open mode), then redirects to the console's callback with a one-time code.
- Tokens are RS256 JWTs signed with a key kept in `NNACCOUNT_DATA`; `links.json` maps Nintendo Account ids to Nextendo PIDs.

`go build` · `NNACCOUNT_LISTEN`, `NNACCOUNT_DATA`, `NNACCOUNT_ACCOUNT_URL`, `NEXTENDO_INTERNAL_KEY`, `NNACCOUNT_DEFAULT_PID`.

## Credits

Built by nx-mod for the **Nextendo Network**, on the work of the Nextendo Network team — https://nextendo.network. Nextendo is awesome.
