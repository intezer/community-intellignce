# EchoGather / GOFFEE Campaign — IOCs

## SHA256 Hashes

### XLL Loaders

| SHA256 | C2 |
|--------|-----|
| `0506a6fcee0d4bf731f1825484582180978995a8f9b84fc59b6e631f720915da` | fast-eda[.]my |
| `aa5b0bba424383d52d37681426246a9110a0008484755b57f500fffbe3960710` | timecheck[.]site |
| `d213485e36e952149a694b79751c9d481abcb67ad034ce31126f34884cdb6b67` | timecheck[.]site |
| `bcdfb6e2feb3cfb1b17641d180c72edfeec45d25ba3c2fada715b1bb5b1e6fcd` | timecheck[.]site |
| `5447eeadc1684975c34fbe1df5056536a8d3bdea3425f9117ff94be143564892` | timecheck[.]site |
| `23d917781e288a6fa9a1296404682e6cf47f11f2a09b7e4f340501bf92d68514` | fast-eda[.]my |

### EchoGather Beacons (PE32+ EXE / DLL)

| SHA256 | C2 |
|--------|-----|
| `74fab6adc77307ef9767e710d97c885352763e68518b2109d860bb45e9d0a8eb` | fast-eda[.]my |
| `b2419afcfc24955b4439100706858d7e7fc9fdf8af0bb03b70e13d8eed52935c` | fast-eda[.]my |
| `46fd674c25c3ec4e0613698b3a4e57f1cf285f46ab0d7bbf9c71c1e2f2270a36` | fast-eda[.]my |
| `dd5a16d0132eb38f64293b8419bab3a3a80f48dc050129a8752989539a5c97bf` | fast-eda[.]my |
| `e2e532cd6ae70976a6c73e04f1e46c399d4a1e7d38d572a436ffbb223232761f` | fast-eda[.]my |
| `b1c61dea44685a84e40da5a852e5898eb127ad2753626e7b2c9b62b64c4a2277` | fast-eda[.]my |
| `0d1dd7a62f3ea0d0fbeea905a48ae8794f49319ee0c34f15a3a871899404bf05` | ruzede[.]com |
| `c3e04bb4f4d51bb1ae8e67ce72aff1c3abeca84523ea7137379f06eb347e1669` | ruzede[.]com |
| `d851923aec2feef8f31c1d8b0e7236ac85e8a709154b0c589a03a6f1b14ed606` | easytrns[.]com |
| `2e6a5f570c387a563c05c0caed393fd4598e82f705fdb1ae684460c49bdcf8b6` | easytrns[.]com |
| `b880c3ebaf0d8d845b22d33a84fef393e33c7d1a88ec55c4e5ccebe138aa8d03` | easytrns[.]com |
| `1a47c1c1525d92ec7b8e955c7d397ab29137b84361a0057dc1bd3975fdc07789` | easytrns[.]com |
| `26a1027ecd7ed96eb725e4ea29c00e875a2f9320ddbcc40b567c5f12749659b4` | easytrns[.]com |
| `258f955e68d6bd892d2cf5c9dc8da3b75218d7c9b7e3b9653adf6f96bdf5c55f` | ntpsync[.]online |
| `3555b4769476b6f35c3cfd618f51db3f8a80344f558f7d94facb4b634c39b94e` | ntpsync[.]online |
| `a49e7a76557a049f7625a58fa0328c393f6b0bc8ab0804238882bbabeee00c0b` | timemirror[.]online |
| `359dc1d3b6e4b6d51c1a41d0b9a2ac667283470e5603550c02183d9aafce9818` | timemirror[.]online |
| `5a7aee0b44b02e74dde8ed309a4d78bd77e84032fc1a9518ea8f4e85cd73c95f` | timemirror[.]online |
| `1aabd56bff1d6054ee949119e33f48ac54a8099da852eb26e0ae30a6a5010dbb` | fastchessplay[.]com |

### GOFFEE Extended Cluster (Kaspersky report — not in our samples)

| SHA256 | Family | Notes |
|--------|--------|-------|
| `be1d0faf1c253faacba1059971b01d1d646256d7b2e557da55ed059542afdbcd` | PowerModul | `UserCache.ini`, PS dropper, 6.66 KB |
| `afc7302d0bd55cfc603fdaf58f5483b0cc00d354274f379c75cfa17f6ba6f97d` | Mythic agent | `duplicate.hta` polyglot, ~165 KB |

---

## C2 Domains (confirmed)

```
fast-eda[.]my
timecheck[.]site
ruzede[.]com
easytrns[.]com
ntpsync[.]online
timemirror[.]online
fastchessplay[.]com
```

Full C2 URLs follow a fake-legit-API pattern:

```
https://timecheck[.]site/api/v2/check/ru/moscow/now
https://ntpsync[.]online/sync/now/protocol/standard
https://timemirror[.]online/api/v1.2/ru/time/omsk/now
https://fast-eda[.]my/dostavka/lavka/kategorii/zakuski/sushi/sety/skidki/regiony/msk/birylievo
https://easytrns[.]com/transfer/from/PEHCXFCDHKLGDSM/to/SKHBKLWECXOQ/wqwhpoziuenmcg
https://fastchessplay[.]com/auth/sso/login/mfa/verify/token/dashboard/rating/ladder/top/position
```

---

## Infrastructure IPs (direct hosting, non-CDN)

```
5.45.85.43        — ruzede.com
94.103.3.0
94.103.3.25
94.103.3.82
194.87.218.16
194.87.218.68
62.113.114.117    — PowerModul C2 (Kaspersky)
```

---

## Pivot Cluster Domains (shared banner hash / co-deployed infra)

Shares banner hashes or hosting with confirmed C2s — not all independently confirmed malicious.

```
timesync.cloud
timefetch.online
timeget.online
timemaster.site
timebits.online
timealign.online
timematch.online
rehremade.online   — co-deployed with ruzede.com on 5.45.85.43
2k-line.com
awalitalk.com
```
