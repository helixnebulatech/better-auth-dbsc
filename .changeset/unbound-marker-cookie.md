---
"better-auth-dbsc": patch
---

Stop reading the database on every request of a browser without DBSC. A request with a session cookie and no bound cookie used to cost one `dbscSession` lookup each time, even with `cookieCache` enabled. Once a session can no longer register, the plugin now sets an unbound marker cookie (`dbsc_unbound_<tag>`, an HMAC over the session token, valid for 24 hours), and requests that carry it skip the lookup. The marker is never issued while the session can still become bound, so a session cookie copied before the registration still stops working as soon as the session is bound.

To make that point in time exist, a session can now only register during its first 10 minutes: registration challenges are valid for 5 minutes instead of `challengeMaxAge`, and `/dbsc/start` refuses older sessions. Chrome registers as soon as it receives the offer, so this does not change normal registrations.

`/get-session` also no longer looks for a deferred registration offer once the offer's 5-minute lifetime has passed.
