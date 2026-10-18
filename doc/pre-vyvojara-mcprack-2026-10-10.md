# mcprack – zistenia a návrhy opráv pre správcu (vitex)
*mV-spojovateľ pre Crystal Water s.r.o., 10. 10. 2026. Stav: NEODOSLANÉ – odošle Crystal.*
Inštancia: mcprack.mojavoda.sk (VitexSoftware mcprack v1.5.9, kód overený na commite 6492af9), balík mcp-server-email (Vitexus fork).

## 1. KRITICKÉ – konektory v Claude padajú na „Couldn't reach" (Vaultwarden ~32 s na jedno heslo)
**Príznak:** e-mailové konektory v Claude (custom connector → `/proxy/mcp/<token>/<id>`) sa nepripoja, ďalší pokus občas prejde.
**Dôkaz – auditný log 10. 10. 2026 (UTC), IP 160.79.106.181 = Claude:**
| čas | akcia | server |
|---|---|---|
| 18:47:55 | credential_access success | mcp-email-crystalwater-sales |
| 18:48:29 | credential_access success | mcp-email-mojavoda-info |
| 18:49:01 | credential_access success | mcp-email-mojavoda-obchod |
| 18:49:34 | credential_access success | mcp-email-crystalwater-info |
| 18:50:06 | credential_access success | mcp-email-crystalwater-obchod |
Jedna resolúcia tajomstiev z Vaultwardenu trvá ~32 s a beží sériovo pod spoločným zámkom. Claude čaká na konektor ~30 s. `config.py` pritom uvádza 9–13 s na se-mcp-rack01.
Ďalšie merania: studený štart servera 33–65 s; opakovane `Could not resolve credentials: Vaultwarden is busy (lock wait exceeded 20.0s)`; nečinná proxy sa zastaví po 900 s → po 15 min znova studený štart. Aj admin stránky a `/api/v1/...` počas toho odpovedali 20–60 s, občas 502 z reverzného proxy.
Server s heslom uloženým ako necitlivé (bez Vaultwardenu) štartuje za 2,5–10 s a pripája sa spoľahlivo.

**Návrhy (podľa priority):**
1. Zvýšiť `BW_ENV_CACHE_TTL` (teraz 60 s) napr. na 86400. Pri zápise tajomstva sa cache invaliduje (`secret_store._invalidate_cached_secrets`), takže dlhé TTL nemaskuje zmeny.
2. Zistiť, prečo `unlock → get_notes → lock` trvá ~32 s (latencia na vault.vitexsoftware.com, `bw` CLI, `BITWARDENCLI_APPDATA_DIR`, sync pri každom unlock?). Zvážiť držať session odomknutú namiesto `lock` po každej resolúcii.
3. Alternatíva: presun tajomstiev do lokálneho šifrovaného úložiska (admin „Nastavenie Vaultwardenu" → snapshot to local) a vypnúť `BW_SERVER`.
4. Voliteľne: pri štarte mcprack/po uložení servera predohriať cache pre vybrané (user, server) dvojice; predĺžiť idle (`cleanup_idle_proxies(max_idle_seconds=900)`) pre e-mailové servery.

## 2. Formulár „Úprava servera" ukladá prázdne návrhové riadky
`admin.server_edit` pri každom otvorení doplní kľúče z manifestu (`debian/server.json`), ktoré server nemá nastavené, s prázdnou hodnotou. Po „Save server" sa uložia ako `""`. Pri mcp-server-email prázdne `MCP_EMAIL_SERVER_CREDENTIAL_STORAGE` vyhodí `ValueError` v `_pickup_credential_storage_override` → každý nástroj vráti „Error executing tool".
Obídené: na serveroch 7–17 nastavené `CREDENTIAL_STORAGE=auto`.
**Návrh:** neukladať návrhové riadky s prázdnou hodnotou (alebo ich v `_parse_env_rows` preskočiť, ak neboli pôvodne nastavené); prípadne v mcp-server-email brať prázdny `CREDENTIAL_STORAGE` ako nenastavený.
Súvisiace: pri „Could not load current secret values: Vaultwarden is busy" formulár zobrazí prázdne riadky namiesto hesiel – uloženie by heslá prepísalo. Návrh: v takom prípade zablokovať „Save server". A „Could not save credentials: Vaultwarden is busy" uloží DB časť, ale nie tajomstvá – nekonzistentný stav.

## 3. `list_emails_metadata` bez filtra padá pri veľkej schránke
obchod@crystalwater.sk: INBOX > 10 000 správ (od 2014). S `since=2025-01-01` (8 012 správ) OK za ~12 s, bez filtra „Error executing tool" po ~11 s. Server triedi všetky výsledky podľa INTERNALDATE pred stránkovaním.
**Návrh:** predĺžiť časový limit nástroja, alebo pri absencii filtra obmedziť vyhľadávanie (napr. posledných N UID / SORT na strane IMAP).

## 4. Drobnosti
- Odznak „⚠ 1 required value(s) missing" v zozname serverov nečíta Vaultwarden, preto ukazuje chýbajúce heslo aj tam, kde je uložené (OK hlási len server s necitlivým heslom).
- Server servis@crystalwater (id 12) má `MCP_EMAIL_SERVER_PASSWORD` uložené ako necitlivé (čitateľné cez `/api/v1/admin/servers/12`). Po vyriešení bodu 1 ho prepnúť na citlivé.

Podrobnosti a postupy: `prevadzka/prepojenia/mcprack-email/INSTRUKCIE.md`.
