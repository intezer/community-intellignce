# Paper Werewolf (GOFFEE) — IOCs

Multi-vendor compilation. Each section is attributed to its source report.

---

## Source: Intezer Research — EchoGather Campaign

### SHA256 Hashes

#### XLL Loaders

| SHA256 | C2 |
|--------|----|
| `0506a6fcee0d4bf731f1825484582180978995a8f9b84fc59b6e631f720915da` | fast-eda[.]my |
| `aa5b0bba424383d52d37681426246a9110a0008484755b57f500fffbe3960710` | timecheck[.]site |
| `d213485e36e952149a694b79751c9d481abcb67ad034ce31126f34884cdb6b67` | timecheck[.]site |
| `bcdfb6e2feb3cfb1b17641d180c72edfeec45d25ba3c2fada715b1bb5b1e6fcd` | timecheck[.]site |
| `5447eeadc1684975c34fbe1df5056536a8d3bdea3425f9117ff94be143564892` | timecheck[.]site |
| `23d917781e288a6fa9a1296404682e6cf47f11f2a09b7e4f340501bf92d68514` | fast-eda[.]my |

#### EchoGather Beacons (PE32+ EXE / DLL)

| SHA256 | C2 |
|--------|----|
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

### C2 Domains

```
fast-eda[.]my
timecheck[.]site
ruzede[.]com
easytrns[.]com
ntpsync[.]online
timemirror[.]online
fastchessplay[.]com
```

### C2 URLs (fake-legit-API pattern)

```
https://timecheck[.]site/api/v2/check/ru/moscow/now
https://ntpsync[.]online/sync/now/protocol/standard
https://timemirror[.]online/api/v1.2/ru/time/omsk/now
https://fast-eda[.]my/dostavka/lavka/kategorii/zakuski/sushi/sety/skidki/regiony/msk/birylievo
https://easytrns[.]com/transfer/from/PEHCXFCDHKLGDSM/to/SKHBKLWECXOQ/wqwhpoziuenmcg
https://fastchessplay[.]com/auth/sso/login/mfa/verify/token/dashboard/rating/ladder/top/position
```

### Infrastructure IPs (direct hosting, non-CDN)

```
5.45.85.43        — ruzede.com
94.103.3.0
94.103.3.25
94.103.3.82
194.87.218.16
194.87.218.68
```

### Pivot Cluster Domains (shared banner hash / co-deployed infra)

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

---

## Source: Kaspersky / Securelist — "GOFFEE APT: New Attacks"

Report: https://securelist.com/goffee-apt-new-attacks/116139/  
Activity period: July–December 2024

### File Hashes

| File | MD5 | SHA1 | SHA256 | Family |
|------|-----|------|--------|--------|
| `UserCache.ini` | `60A53D2C653991F086C4E6663D652CF2` | `636814C31B78DD291049029A655238D7ADAFF041` | `be1d0faf1c253faacba1059971b01d1d646256d7b2e557da55ed059542afdbcd` | PowerModul |
| `duplicate.hta` | `615BD8D70D234F16FC791DCE2FC5BCF0` | `EF14D5B97E093AABE82C4A1720789A7CF1045F6D` | `afc7302d0bd55cfc603fdaf58f5483b0cc00d354274f379c75cfa17f6ba6f97d` | Mythic agent (polyglot HTA) |

### IP Addresses / C2

```
62.113.114.117    — PowerModul C2
```

C2 URL pattern:
```
hxxp://62.113.114[.]117/api/texts/{computer_name}_{username}_{serial_number}
```

### File Artifacts

| File | Purpose |
|------|---------|
| `UserCache.ini` | PowerModul script container |
| `UserCache.ini.hta` | HTA launcher |
| `UserCacheHelper.lnk.js` | JavaScript executor |
| `ftree.db` | FlashFileGrabber metadata storage |
| `internal_profiles.db` | MD5 hash tracking |
| `explorer.exe` (patched) | Initial infection vector |
| `xpsrchvw.exe` (patched) | Alternative initial infection vector |
| `ntuser.exe` | Renamed PsExec (privilege escalation) |
| `1cv9.exe` | Renamed PsExec (lateral movement) |

### Persistence

| Registry Key | Value |
|---|---|
| `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows` | `LOAD=C:\Users\<USER>\UserCache.ini.hta` |

---

## Source: BI.ZONE — "Paper Werewolf Targets Russia with WinRAR Zero-Day"

Report: https://bi.zone/eng/expertise/blog/paper-werewolf-atakuet-rossiyu-s-ispolzovaniem-uyazvimosti-nulevogo-dnya-v-winrar/  
Activity: July 2025 | CVE exploited: CVE-2025-6218 (WinRAR directory traversal RCE) + second zero-day

### File Hashes

| File | MD5 | SHA1 | SHA256 |
|------|-----|------|--------|
| `minprom_04072025.rar` | `9a69b948e261363463da38bdbf828b14` | `40e647d61a00fd7240e54dba45ce95c5d33cae43` | `fe2587dd8d9755b7b3a106b6e46519a1ce0a8191eb20821d2f957326dbf912e9` |
| `xpsrchvw.exe` | `942220fc9382f44ae82061d1fc63f41e` | `7ff3d32e78c5626135a73bba4a011058f714ae86` | `bf74820d40d281c28d5928b01e5b68d6caf85b5b9188bf4efb627765d708bcff` |
| `Запрос_Минпромторг_22.07.rar` | `6b4d7a63aa2a8b2a5a3fbad6c8e6533e` | `d3820a1248bf54ce8a3d05bf688bcd97e1c41d8e` | `28a2b98ae214376ccd549a8b0dccafad31c8b234d0b81a0e8817579566615567` |
| `DON_AVIA_TRANS_UZ.rar` | `eaba94b5237d2625fa38bc924e5347c4` | `6c0e52b8ed746b5b8ebef1ef2226093260659ae8` | `d2c3fe8b9a4e0e5b7bcc087d52295ab30dc25b1410f50de35470383528c9d844` |
| `DON_AVIA_TRANS_RU.rar` | `d176b7b5040d7bb32bae4d5c3c3b6aaf` | `b610ff2ad9791d17203609d747c5dfe947304591` | `dfab2f25c9d870f30bbc4abb873d155cf4904ece536714fb9cd32b2e0126dfab` |
| `WinRunApp.exe` (sample 1) | `1670035385c9031f79566c6f73fb9743` | `b7bba4a216f4910f5072019bb4a2022ccf098c75` | `2446f97c1884f70f97d68c2f22e8fc1b9b00e1559cd3ca540e8254749a693106` |
| `WinRunApp.exe` (sample 2) | `67daddd8fd8a59c8b3d40ea433efd6ff` | `23708d1fdcd7ba65c2b2fc676cee707e746a2dd9` | `236aba76d427111e8c140604ead9c4ab86264b1ae197fc26fadb33c46be94289` |

### IP Addresses

```
89.110.88.155     — reverse shell C2 (port 8090)
81.30.105.148
213.171.4.200
89.110.98.26
94.242.51.73
```

### Domains / C2

```
eliteheirs[.]org
indoorvisions[.]org
trailtastic[.]org
```

### C2 URLs

```
hxxps://eliteheirs[.]org/checks/brandished/dyestuffs/abbess/interrelation
hxxps://eliteheirs[.]org/crossness/outpost/autocracies/decapitations/jetsetting
hxxps://indoorvisions[.]org/patriarchal/furthering/creating/flared/censured
hxxps://trailtastic[.]org/glowworms/diverted/calorie/britons/parabolas
```

### Mutexes

```
Sfgjh824nf6sdfgsfwe6467jkgg3vvvv3q7657fj436jh54HGFa56
Global_22576733
```

### Persistence / File Paths

```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\xpsrchvw74.exe
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\xpsrchvw71.exe
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\xpsrchvw72.exe
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\xpsrchvw73.exe
%LOCALAPPDATA%\WinRunApp.exe
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WinRunApp.lnk
```

---

## Source: BI.ZONE — "Unholy Trinity: Werewolves Target Law Enforcers" (Paper Werewolf portion only)

Report: https://bi.zone/eng/expertise/blog/triedinoe-zlo-oborotni-atakuyut-sotrudnikov-silovykh-struktur/  
Activity: February 2026 | Published: April 2026  
Note: Report covers three clusters (Paper Werewolf, Versatile Werewolf, Eagle Werewolf). Only Paper Werewolf IOCs are listed here.

### File Hashes (SHA256)

| File / Family | SHA256 |
|---|---|
| C# Dropper (sample 1) | `9292fae9b63203cdc0cb204b53314d056e01fc760707dcaa89e66e43d688b25e` |
| C# Dropper (sample 2) | `4263c458ef216f8e2524462ea3efe79be44492d51143a519081c429c3c24c166` |
| Decoy document | `c1fbd66467449d3c8d9d07a939843a49fad9de9ac484241d52f0d5a94299ca62` |
| EchoGather RAT (sample 1) | `e1f359773da3b014389018ef8a22a15acb2157b43cff5f507237ca7093174b11` |
| EchoGather RAT (sample 2) | `f8c10fd2b3d254cff0c7927c188a7751568fe7ff3eace1de83bb3148bc14a339` |

### IP Addresses

```
104.194.158[.]63
```

### Domains / C2

```
syncheaven[.]online
battleflight[.]org
battleflight[.]pro
certcheck[.]online
re-link[.]space
mystarlink[.]org
web-tellegram[.]org
```

### C2 URLs

```
hxxps://syncheaven[.]online/sync/now/ru/moscow/fetch
hxxps://battleflight[.]org/download/installer
hxxps://battleflight[.]pro/static/media/BattleFlight_Installer.exe
hxxps://certcheck[.]online/certificate/check/Wi5kyh3yFeUF2VhIiFX572eR3870GxYrk7f1Q7MLV5vJ3xGnf4
hxxps://web-tellegram[.]org/ru
```

### Lure Files / Malware Filenames

```
Registration_Starlink.exe        — EchoGather RAT disguised as Starlink registration app
BattleFlight-Install-v11.0.3.exe — EchoGather RAT disguised as drone control app
```

### Persistence / File Paths

```
%APPDATA%\Microsoft\Windows\mssw.exe   — EchoGather payload
%APPDATA%\Microsoft\Windows\msms.exe   — EchoGather payload (alternate)
```
