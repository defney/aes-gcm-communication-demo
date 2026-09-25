# Oturumluk C++ AES-GCM / ECDH demosu

Bes kaynak dosyasi birlikte kullanilir:
- app1.cpp: Menu uygulamasinin giris noktasi.
- app2.cpp: Client uygulamasinin giris noktasi.
- ipc_protocol.h: surumlu mesaj duzeni.
- session_crypto.h: ortak kripto ve uygulama arayuzu.
- session_crypto.cpp: ECDH, AES-GCM, iki yonlu IPC, konsol girisi ve temizlik.

App1 ve App2 kisa tutuldu: ayni kodun iki farkli kopyasinin bozulmamasi
icin ortak islemler session_crypto.cpp icindedir. Her exe'nin RAM'i ve
ECDH anahtarlari ayridir.

## Derleme

Eski exe'ler calisiyorsa once kapatin. MinGW:

```powershell
g++ -std=c++17 -Wall -Wextra app1.cpp session_crypto.cpp -o app1.exe -lbcrypt -luser32 -static-libgcc -static-libstdc++
g++ -std=c++17 -Wall -Wextra app2.cpp session_crypto.cpp -o app2.exe -lbcrypt -luser32 -static-libgcc -static-libstdc++
```

## Calistirma

Ilk PowerShell penceresi: `.\app2.exe`

Ikinci PowerShell penceresi: `.\app1.exe`

Her iki konsolda parola yazip Enter'a basin. App2'ye girilen yeni parola
App1'e gider; App1'deki parola App2'ye gider. Giris yildizlarla gizlenir;
alinan acik parola konsola yazilmaz. Basarili cozum ve bayt sayisi yazilir.
Parola UTF-8 olarak 1-60 bayt olabilir. Pencere acik kalir ve tekrar
gonderim yapilabilir. Her iki tarafta `/quit` + Enter veya Ctrl+C,
dogrulanmis kapatma mesaji gonderip iki tarafi kapatir.

## Test

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test.ps1
```

Test kendi ayri kanalinda iki surec acar: normal iki yonlu aktarim,
bozuk tag/ciphertext, yanlis surum, eksik mesaj, replay, kontrollu kapanis
ve App2 kapali durumu. Yalnizca sabit test parolalari kullanir.
Uygulamalar key.bin, secret.bin veya password.verifier okumaz/yazmaz.
Eski dosyalariniz otomatik silinmez.

## Tasarim ve sinirlar

- ECDH P-256 anahtar cifti her uygulama oturumunda yenilenir. Ortak sir
  CNG HASH KDF (SHA-256) ile iki yon icin ayri AES-256 anahtarina donusur.
  Iki acik anahtar da turetme baglamina katilir; ECDH gizli anahtari ve
  ortak sir turetme bittiginde serbest birakilir.
- Surum 2 mesaji 108 bayttir: surum/tur/sira 16, nonce 12, tag 16,
  ciphertext 64. Ilk 16 bayt GCM AAD ile dogrulanir. Eski 96 baytlik
  demo ile karistirmayin; her iki exe'yi birlikte yeniden derleyin.
- Nonce, her yonun ayri anahtari altinda 0'dan baslayan bir sayactan
  turetilir (ilk kullanilan sira 1). Ayni anahtar altinda tekrar etmez.
  Her mesajda rastgele nonce yerine bu sayac kullaniliyor.
- Sira kontrolu replay'i reddeder. Kapatma mesaji da AES-GCM ile korunur.
- SendMessageTimeoutW, WM_COPYDATA uzerinden gonderir. Alici callback
  icinde konsol girisi beklenmez. Gelen veri callback icinde kopyalanir.
  Referans: https://learn.microsoft.com/en-us/windows/win32/dataxchg/wm-copydata
- Bu bir prototiptir: ECDH tek basina karsi tarafin kimligini dogrulamaz.
  HWND/PID eslesmesi yalnizca tutarlilik kontroludur; sahte client/menu
  veya aktif araya girme saldirisina karsi guclu kimlik dogrulamasi degildir.
  Gercek Menu/Client entegrasyonunda guvenilen baslatma/kimlik mekanizmasi gerekir.
- Parolalar bilerek diske yazilmaz; Windows paging/crash dump ve ayni
  sureci okuyabilen saldirganlara karsi RAM'de mutlak gizlilik garantisi yoktur.
  Acik tamponlar kapsam sonunda SecureZeroMemory ile silinir; zorla surec
  sonlandirmada normal kapanis kodunun calismasi garanti degildir.
- KP veritabani guncellemesi bu demoda yoktur. Menu tarafinda dogrulanmis
  parolanin alindigi yer kodda isaretlidir. Yalnizca sifreli kopya oturumda tutulur.

## Kontrol edilen sonuc

MinGW ile -Wall -Wextra -Wpedantic kullanilarak iki exe derlendi.
Normal ve olumsuz iki yonlu IPC testleri ile kapali client testi gecti.
