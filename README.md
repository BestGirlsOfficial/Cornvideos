# Videótér 18+

## Indítás saját gépen (Python 3.10+)
    pip install -r requirements.txt
    flask --app app admin      # admin fiók létrehozása
    flask --app app run        # http://127.0.0.1:5000

## Élesítés
- `HTTPS=1 gunicorn -w 3 --timeout 600 app:app`, elé HTTPS-t adó proxy (pl. Caddy vagy nginx, 500 MB feltöltési limittel).
- A `data/` mappa (adatbázis, videók, titkos kulcs) legyen mentve és ne legyen nyilvánosan kiszolgálva.
- Olyan tárhelyet válassz, amely engedi a felnőtt tartalmat.

## Nyilvános indulás ELŐTT kötelező
1. Valódi életkor-ellenőrzés: a születési dátum megadása önbevallás, ez jogilag általában nem elég. Külső ellenőrző szolgáltatót kell bekötni.
2. A szereplők igazolványának és írásos hozzájárulásának bekérése és biztonságos megőrzése (a kód ezt nem tárolja, csak az admin nyugtázását).
3. Jogász: szabályzat, adatkezelési tájékoztató (GDPR), EU DSA, magyar gyermekvédelmi szabályok.
4. Kapcsolattartó e-mail a `templates/rules.html` fájlban.
5. Belépési próbálkozások korlátozása (rate limit) a proxyban vagy az appban, és vírus-/tartalomszűrés a feltöltésekre.

Gyanús, kiskorút érintő anyagot ne nézegess tovább és ne másolj: jelentsd a rendőrségnek vagy az NMHH Internet Hotline-nak.

## Még nincs benne
Elfelejtett jelszó, e-mail, videó-átkódolás, bélyegképek, lapozás, keresés.
