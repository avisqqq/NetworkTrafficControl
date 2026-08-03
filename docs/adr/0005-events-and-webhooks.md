# 5. Zdarzenia i webhooki zamiast systemu alertów

Status: Accepted — 2026-08-02

> Ten rekord jest napisany po polsku, w przeciwieństwie do 0001–0004. Powód: opisuje
> mechanizm, którego nie budowaliśmy wcześniej, i ma być zrozumiały bez wcześniejszej
> wiedzy o webhookach. Jeśli seria ma być spójna językowo, tłumaczymy całość naraz.

## Słowniczek

Rekord używa kilku pojęć, które nie są oczywiste. Wyjaśnione tu raz, żeby dalej
czytało się płynnie.

**Zdarzenie (event)** — fakt, który zaszedł w systemie i jest wart odnotowania.
Nie polecenie, nie pytanie — stwierdzenie w czasie przeszłym. „Dodano `1.2.3.4`
do czarnej listy", „wykryto skanowanie portów", „usługa wystartowała".

**Webhook** — sposób powiadamiania, w którym **my** wysyłamy żądanie HTTP na adres
podany przez odbiorcę. Odwrotność zwykłego API: tam ktoś pyta nas, tu my mówimy
jemu. Nazwa jest myląca — to po prostu „POST na URL, który ktoś nam wcześniej dał".

**Subskrypcja** — zapisana w bazie para: *jakie zdarzenia* + *na jaki URL wysłać*.
Jeden użytkownik może mieć wiele subskrypcji.

**Payload** — treść wysyłanego żądania, czyli JSON w ciele POST-a.

**HMAC** — podpis kryptograficzny obliczany z treści i wspólnego sekretu.
Odbiorca liczy go u siebie i porównuje. Jeśli się zgadza, wie, że wiadomość
naprawdę pochodzi od nas i nikt jej po drodze nie zmienił.

**Outbox** — tabela w bazie, do której zapisujemy zdarzenie zamiast wysyłać je
od razu. Osobny proces czyta z niej i wysyła. Nazwa jak „skrzynka nadawcza"
w kliencie poczty i znaczenie dokładnie takie samo.

**At-least-once** — gwarancja „co najmniej raz". Wiadomość na pewno dojdzie,
ale może dojść dwa razy. Przeciwieństwo to *at-most-once* (najwyżej raz — może
zginąć) i *exactly-once* (dokładnie raz — w praktyce nieosiągalne przez sieć).

**Backoff** — odczekanie przed ponowieniem nieudanej próby, z rosnącą przerwą:
10 s, 30 s, 2 min, 10 min. Chroni odbiorcę, który ma awarię, przed dobiciem
go naszymi ponowieniami.

**Idempotencja** — właściwość operacji, którą można wykonać wielokrotnie
z tym samym skutkiem co raz. Potrzebna po stronie odbiorcy, bo dostarczamy
*at-least-once*.

**SSRF** (Server-Side Request Forgery) — atak, w którym napastnik zmusza nasz
serwer do wysłania żądania w miejsce, do którego sam nie ma dostępu. Nasz serwer
staje się jego pośrednikiem.

---

## Kontekst

### Co mamy dziś

Trzy pliki, około 90 linii, których **nic w kodzie nie używa**:

- `source/domain/alert/alert.go` — struktura `Alert`
- `source/application/alerts/rule.go` — interfejs `Rule` i typ `Match`
- `source/application/alerts/forbidden_ip_rule.go` — jedna reguła
- `config.yaml` — zakomentowana sekcja `telegram` / `webhook_url`

Nie ma silnika, który wołałby `Evaluate`. Nie ma nic, co wysyłałoby powiadomienie.
Nie ma zapisu. Struktura `Alert` ma pole `DeduplicationKey`, którego nikt nie czyta.

### Problem, który naprawdę rozwiązujemy

Nie brzmi on „chcemy alerty". Brzmi:

> Użytkownik nie siedzi w naszym UI. Ma się dowiedzieć, że w jego sieci coś się
> stało, w miejscu, w którym akurat jest.

To jest szersze niż alerty bezpieczeństwa. „Wykryto skanowanie portów" i „ktoś
usunął regułę blokującą" to dla użytkownika ta sama potrzeba — chce wiedzieć.
System, który obsługuje tylko pierwsze, będzie trzeba rozbudowywać o drugie,
i powstaną dwa mechanizmy robiące to samo.

### Pierwszy rozważany pomysł i dlaczego go odrzuciliśmy

Naturalna droga to: dokończyć `alerts` — dopisać silnik, który przepuszcza każdy
pakiet przez reguły, a przy trafieniu woła `Notifier` (interfejs z implementacjami
pod Telegram i webhook).

Zadziałałoby. Ma jednak wadę, która ujawnia się dopiero przy trzeciej funkcji:
**reguła wie o powiadomieniu**. Detekcja i wysyłka są w jednym łańcuchu. To znaczy,
że dodanie nowego kanału powiadomień dotyka kodu detekcji, a dodanie detektora
dotyka kodu powiadomień. Dodatkowo obejmuje wyłącznie zdarzenia wykryte
w pakietach — „usunięto regułę" nie ma jak przez ten system przejść, bo nie jest
pakietem.

### Ograniczenie, o którym trzeba pamiętać

`packetstream.Dispatcher` woła konsumentów **po kolei, w jednej gorutynie**
(`dispatcher.go:31`). Cokolwiek podepniemy do strumienia pakietów, nie może
wykonywać żądań HTTP w miejscu — POST trwający 300 ms wstrzymuje SSE, metryki
i analitykę na te 300 ms. Przy odbiorcy z timeoutem 10 s tracimy strumień.
To nie jest teoretyczne; to ta sama klasa błędu co dwa, które już znaleźliśmy.

---

## Decyzja

**Budujemy ogólny mechanizm zdarzeń z dostarczaniem przez webhooki. Alerty
przestają być osobnym bytem i stają się jednym z typów zdarzeń.**

Poniżej sześć decyzji składowych, każda z uzasadnieniem.

### 1. Trzy osobne byty, nie jeden

Największym źródłem zamieszania było traktowanie „zdarzeń" jako jednej rzeczy.
Są trzy i mają różne czasy życia:

| byt | odpowiada na pytanie | przykład | gdzie żyje |
| --- | --- | --- | --- |
| **typ zdarzenia** | co *może* się stać | `list.entry.added` istnieje jako pojęcie | w kodzie |
| **wystąpienie** | co się *stało* | `1.2.3.4` dodany o 14:32 | tabela `events` |
| **subskrypcja** | kto chce wiedzieć | `list.*` → `https://…` | tabela `subscriptions` |

Typ jest definicją i istnieje zawsze. Wystąpienie jest faktem historycznym.
Subskrypcja jest konfiguracją użytkownika.

### 2. Katalog typów mieszka w kodzie, nie w bazie

```go
// source/domain/event
type Type string

const (
    ListEntryAdded    Type = "list.entry.added"
    ListEntryRemoved  Type = "list.entry.removed"
    SystemStarted     Type = "system.started"
    DetectorTriggered Type = "detector.triggered"
)
```

Rozważaliśmy tabelę `event_types` w bazie. Odrzucone, bo błąd jest niesymetryczny:

- typ **w bazie, którego kod nie emituje** → UI pokazuje pozycję do wyboru,
  użytkownik subskrybuje i czeka na powiadomienie, które nigdy nie przyjdzie.
  Nic nie sygnalizuje błędu.
- typ **emitowany przez kod, nieobecny w bazie** → błąd w czasie działania albo
  ciche zgubienie zdarzenia.

Nie ma sposobu, żeby baza była źródłem prawdy o tym, co kod potrafi wyemitować —
kod nim jest z definicji. Baza może być tylko jego nieaktualną kopią.

Drugi powód jest specyficzny dla Go: mamy kompilator. Literówka
w `"list.entry.aded"` **nie skompiluje się**, jeśli typy są stałymi. Trzymanie
ich jako stringów w bazie oddaje tę kontrolę za nic.

Katalog wystawiamy przez `GET /api/events/types` — UI buduje z tego listę wyboru
przy zakładaniu subskrypcji. Nazwy są hierarchiczne z kropką, żeby subskrypcja
mogła używać wzorca (`list.*`, `*`).

### 3. Detektor to dane. Typ zdarzenia zostaje w kodzie

To najmniej oczywista część decyzji i warto ją zrozumieć, bo od niej zależy,
czy katalog w kodzie w ogóle się utrzyma.

Chcemy, żeby w przyszłości dało się dodawać detektory (np. wykrywanie skanowania
portów), łącznie z definiowaniem ich przez użytkownika w UI. Wygląda to na
sprzeczność: skoro użytkownik tworzy detektor, to tworzy nowy rodzaj zdarzenia,
więc rodzaje muszą być w bazie.

**Nie muszą.** Detektor nie definiuje nowego typu — emituje znany typ
`detector.triggered`, a to, *który* detektor zadziałał, jest polem w treści:

```json
{
  "type": "detector.triggered",
  "timestamp": "2026-08-02T14:32:11Z",
  "data": {
    "detector_id": "port-scan",
    "detector_name": "Skanowanie portów",
    "severity": "critical",
    "src_ip": "192.168.1.55",
    "matched": "22 różne porty w 10 s"
  }
}
```

Subskrypcja filtruje po typie **i opcjonalnie po polu treści**
(`detector_id = "port-scan"`). Z punktu widzenia użytkownika efekt jest taki sam,
jakby każdy detektor miał własny typ — a katalog zostaje mały i sprawdzany
przez kompilator.

Tak samo działa GitHub: nie ma typu `issue.labeled.bug`, jest `issues`
z `action: labeled` i filtruje się po treści.

**Wniosek:** podział na zdarzenia „systemowe" i „customowe" nie jest podziałem
w mechanizmie. To po prostu inny prefiks: `system.*` i `list.*` kontra
`detector.triggered`. Jeden mechanizm, dwa rodzaje treści.

### 4. Webhook jako jedyny transport

Rozważane sposoby powiadamiania:

| sposób | na czym polega | ograniczenie |
| --- | --- | --- |
| **webhook** | my robimy POST na URL odbiorcy | odbiorca musi mieć osiągalny URL |
| **polling** | odbiorca pyta `GET /api/events?since=…` | opóźnienie, ciągłe obciążenie |
| **SSE / WebSocket** | trwałe połączenie, pchamy na bieżąco | działa tylko gdy odbiorca jest online |
| **integracja natywna** | osobny kod pod Telegram, Slack, e-mail | osobny kod na każdą platformę |

Wybieramy webhook, bo jest jedyny **uniwersalny**: pozostałe trzy da się zbudować
na webhookach, ale nie odwrotnie.

To rozwiązuje też wymaganie „nie chcemy pisać pod konkretne platformy". Discord,
Slack, n8n, Zapier i IFTTT **przyjmują zwykłe webhooki** — użytkownik wkleja URL
z Discorda i to działa bez linijki kodu po naszej stronie.

Wyjątkiem jest Telegram, który wymaga własnego kształtu JSON-a
(`{"chat_id": …, "text": …}`). Dlatego subskrypcja dostaje pole `kind`:
`generic` na start, a `telegram` jako mały adapter przepakowujący treść,
dopisany wtedy, gdy będzie potrzebny. Adapter to jeden plik w `infrastructure`
i nie dotyka reszty systemu.

### 5. Format wiadomości: Standard Webhooks

Wysyłamy POST z trzema nagłówkami zgodnymi ze specyfikacją
[Standard Webhooks](https://www.standardwebhooks.com/) (używaną m.in. przez
OpenAI, Anthropic i Svix):

```
webhook-id:        evt_01H8XG…          identyfikator zdarzenia
webhook-timestamp: 1754140800           czas wysyłki, unix, sekundy
webhook-signature: v1,K5oZfzN95Z9UVu1E… podpis HMAC-SHA256, base64
```

Podpis liczymy z `id.timestamp.payload` (sklejone kropkami), kluczem jest sekret
generowany osobno dla każdej subskrypcji i pokazany użytkownikowi raz,
przy tworzeniu.

**Dlaczego podpisujemy id i czas razem z treścią, a nie samą treść:** gdyby podpis
obejmował wyłącznie treść, ktoś kto raz przechwycił nasze żądanie, mógłby je
odtwarzać w nieskończoność — podpis nadal by się zgadzał. Z czasem w podpisie
odbiorca odrzuca wszystko starsze niż np. 5 minut.

`webhook-id` służy odbiorcy równocześnie jako klucz idempotencji — patrz
konsekwencje niżej.

Treść jest nasza, ale z trzema polami konwencjonalnymi: `type`, `timestamp`, `data`.

Implementujemy sami — to około 30 linii na `crypto/hmac`, `crypto/sha256`
i `encoding/base64` ze standardowej biblioteki. Biblioteka istnieje, ale przy
sześciu bezpośrednich zależnościach w `go.mod` i budowaniu na ARM nie warto
dokładać siódmej dla trzydziestu linii.

### 6. Dostarczanie przez outbox

Wersja naiwna — „zdarzenie zaszło → wyszukaj subskrypcje → POST" — ma cztery wady:

1. blokuje kod, który wyemitował zdarzenie (patrz ograniczenie dispatchera wyżej),
2. proces pada między zapisem zmiany a wysłaniem → zdarzenie znika bez śladu,
3. odbiorca ma minutową awarię → zdarzenie przepada, choć wystarczyłoby ponowić,
4. nie wiadomo, co zostało wysłane ani czy doszło.

Stosujemy wzorzec **transactional outbox**:

> Zdarzenie zapisujemy do tabeli **w tej samej transakcji bazodanowej**, co zmianę,
> która je wywołała. Osobna gorutyna czyta niedostarczone wiersze i wysyła.

Dzięki temu „reguła została dodana" i „zdarzenie o dodaniu reguły istnieje" są
nierozłączne — albo jedno i drugie, albo nic. Nie ma stanu pośredniego, w którym
zmiana zaszła, a powiadomienie o niej zginęło.

Mamy SQLite i gorm, więc to jest **dwie tabele i jedna gorutyna**. Żadnego brokera,
żadnej biblioteki.

```
kod domenowy
    │   Publish(ctx, tx, event)      ← INSERT w tej samej transakcji
    ▼
[ events ] ──┐
             │  worker (gorutyna, pętla co N sekund)
             ▼
        [ deliveries ] ──→  sink: webhook   (dla każdej pasującej subskrypcji)
                       ──→  sink: appLog    (zawsze, nie da się wyłączyć)
                       ──→  sink: SSE       (podgląd na żywo w UI)
```

**Dwie tabele, nie jedna — to jest szczegół, w którym łatwo się pomylić:**

```
events                            deliveries
------                            ----------
id             ULID               id
type                              event_id         → events.id
occurred_at                       subscription_id  → subscriptions.id
payload        JSON               status           pending | delivered | failed
                                  attempts
                                  next_attempt_at
                                  last_error
                                  response_code
```

Powód: jedno zdarzenie z trzema subskrypcjami to **trzy niezależne dostarczenia**
z niezależnymi ponowieniami. Gdyby status siedział w `events`, jeden padnięty
odbiorca fałszowałby stan dla dwóch pozostałych.

**Ponowienia:** backoff wykładniczy z losowym rozrzutem (10 s, 30 s, 2 min,
10 min, 1 h), limit prób, a po N kolejnych porażkach subskrypcja zostaje wyłączona
i fakt wyłączenia jest zapisany jako zdarzenie systemowe. System, który powiadamia
o tym, że przestał powiadamiać, jest zaskakująco użyteczny.

`Sink` jest interfejsem, webhook jedną z implementacji. SSE jako sink daje
powiadomienia na żywo w UI za darmo, bez drugiego mechanizmu.

### Czego świadomie nie robimy: szyny zdarzeń w pamięci

Rozważaliśmy in-memory event bus (`go-eventbus`, `watermill`, albo własny
na kanałach i mapie subskrybentów).

Niepotrzebne, bo **jeśli mamy outbox, to baza jest szyną**. Emisja to `INSERT`,
konsumpcja to odczyt przez workera. Dołożenie do tego drugiego mechanizmu
w pamięci daje dwa tory robiące to samo, z czego jeden gubi dane przy restarcie —
i stałe pytanie „którym torem poszło to zdarzenie". Watermill zaczyna mieć sens
przy prawdziwym brokerze, którego nie mamy i nie potrzebujemy.

### Umiejscowienie w warstwach

```
source/domain/event/            Event, Type            (fakty i słownik pojęć)
source/application/events/      Publisher, Store,      (porty i logika)
                                Subscription, Sink,
                                Worker
source/infrastructure/storage/  repozytorium gorm      (adapter)
source/infrastructure/webhook/  sink HTTP + podpis     (adapter)
```

Zgodne z ADR 0001: `Store` i `Sink` to interfejsy deklarowane w `application`,
czyli tam, gdzie są używane; implementacje w `infrastructure`.

---

## Konsekwencje

### Alerty znikają jako osobny byt — to upraszcza, nie komplikuje

`domain/alert.Alert` w obecnej postaci przestaje być potrzebny: alert to zdarzenie
typu `detector.triggered`. Interfejs `Rule` zostaje, ale zamiast `Match` zwraca
zdarzenie. Nie budujemy dwóch systemów obok siebie — kodu jest mniej, nie więcej.

Przy okazji: `Alert` osadzał całą strukturę `packet.Packet`, czyli surowe `[16]uint8`
adresów i `Ts` w nanosekundach od startu systemu. To reprezentacja jądra, a nie
zdarzenia biznesowego — i tak wymagałaby spłaszczenia przed zapisem i wysyłką.
W nowym kształcie treść zdarzenia jest od razu tym, co idzie do JSON-a.

### Detekcja jest odsprzężona od powiadamiania

To główny zysk. Reguła emituje zdarzenie i **nie wie, kto słucha**. Dodanie
detektora nie dotyka kodu powiadomień; dodanie Telegrama nie dotyka detektorów.
Różnica ujawnia się przy trzeciej i czwartej funkcji, czyli tam, gdzie projekty
zwykle się rozjeżdżają.

### Dostarczamy at-least-once, więc duplikaty się zdarzą

Scenariusz: wysłaliśmy, odbiorca odebrał i przetworzył, my padliśmy przed
zapisaniem `delivered`. Po restarcie wysyłamy ponownie.

Nie da się tego wyeliminować — dlatego w nagłówku jest `webhook-id`, którego
odbiorca ma używać jako klucza idempotencji („ten identyfikator już widziałem,
pomijam"). **To musi znaleźć się w dokumentacji dla odbiorcy**, bo bez tego
duplikat wygląda jak nasz błąd.

### Powiadomienie przychodzi z opóźnieniem

Outbox jest z definicji *eventually consistent*: worker czyta w pętli, więc między
zdarzeniem a POST-em mijają sekundy. Świadomie wybieramy „na pewno dojdzie,
z opóźnieniem" zamiast „natychmiast albo wcale". W narzędziu bezpieczeństwa
„alert o ataku zginął, bo proces się zrestartował" to porażka produktu, a nie
niedogodność.

### Tabela rośnie, a to jest Raspberry Pi

Każde zdarzenie to zapis na kartę SD, która ma ograniczoną liczbę cykli.
Analityka już pisze. Potrzebna jest retencja od pierwszego dnia:
kasowanie `events` starszych niż ustalony okres i czyszczenie `deliveries`
ze statusem `delivered`. Odkładanie tego oznacza, że pierwszy kontakt z problemem
nastąpi przy pełnej karcie.

### SSRF — na bramie sieciowej to nie jest zagrożenie teoretyczne

Kto może założyć subskrypcję, ten może wskazać dowolny URL. NTC działa na bramie,
czyli widzi sieć, której osoba z zewnątrz nie widzi. To znaczy, że webhooki
stają się prymitywem do skanowania cudzej sieci:

- `http://192.168.1.1/` — panel administracyjny routera,
- `http://127.0.0.1:8086/api/lists` — **nasze własne API, które nie ma
  uwierzytelniania** (odnotowane w ADR 0003),
- seria subskrypcji po `192.168.1.0/24` — mapowanie LAN-u naszymi rękami.

Minimum, które przyjmujemy:

- odrzucanie adresów prywatnych i loopback **po rozwiązaniu nazwy DNS**, nie przed —
  bo `evil.example.com` może wskazywać na `127.0.0.1`,
- tylko schematy `http` i `https`,
- twardy timeout, limit rozmiaru odpowiedzi, brak podążania za przekierowaniami
  (przekierowanie omija kontrolę adresu wykonaną przed żądaniem).

### Więcej ruchomych części

Zamiast „wyślij POST" mamy tabelę, workera, stany dostarczenia i politykę
ponowień. To jest realny koszt utrzymania i debugowania. Kupujemy za niego
trwałość, ponowienia i historię — czyli rzeczy, których w prostszym wariancie
nie da się dołożyć później bez przepisania.

### Relacja do ADR 0004

Mechanizm jest niezależny od tego, czy pakiety pochodzą z eBPF czy z NFLOG.
Zdarzenia są emitowane przez `application`, a nie przez czytnik pakietów, więc
przejście egzekucji na nftables nie dotyka niczego opisanego tutaj.

---

## Alternatywy odrzucone

**Katalog typów w bazie.** Odrzucony na niesymetryczności błędu opisanej w decyzji 2:
typ w bazie bez kodu, który go emituje, jest cichym kłamstwem wobec użytkownika.
Kusił możliwością dodawania typów bez wdrożenia — ale i tak nie da się dodać
*emisji* bez wdrożenia, więc zysk był pozorny.

**Osobny typ zdarzenia dla każdego detektora.** Odrzucony na rzecz
`detector.triggered` z filtrem po treści. Wymuszałby katalog w bazie i przenosił
całą powyższą wadę.

**[CloudEvents](https://cloudevents.io/) jako koperta.** Poważnie rozważony:
projekt CNCF w statusie *graduated* od stycznia 2024, realnie wdrażany
(Intuit migruje webhooki QuickBooks z terminem lipiec 2026). Odrzucony, bo
rozwiązuje problem routingu zdarzeń między systemami w chmurze — ma tryby
binary/structured, rozszerzenia i mapowania na Kafkę i AMQP. Dla nas 90% tego jest
martwe, a kosztem jest sztywna koperta, którą każdy odbiorca musi rozpakować.
Standard Webhooks jest mniejszy i dotyczy dokładnie naszego problemu.

**Integracje natywne pod Telegram/Slack/e-mail jako podstawa.** Odrzucone:
każda platforma to osobny kod, osobna konfiguracja i osobne błędy, a większość
z nich i tak przyjmuje zwykłe webhooki. Jako warstwa opcjonalna nad webhookami —
tak, jako fundament — nie.

**Wysyłka bezpośrednio z miejsca zdarzenia, bez outboxu.** Odrzucona na czterech
wadach wymienionych w decyzji 6, z których druga (utrata przy restarcie) jest
dyskwalifikująca dla narzędzia bezpieczeństwa.

**Biblioteka event bus (`watermill` i podobne).** Odrzucona: baza z outboxem
już pełni tę rolę, a drugi mechanizm oznaczałby dwa tory i niejasność, którym
poszło konkretne zdarzenie.

---

## Kolejność budowy

Zaczynamy od zdarzeń systemowych (`list.entry.added` / `list.entry.removed`),
**nie od detektora ataku**.

Powód jest praktyczny: zdarzenia systemowe są rzadkie, deterministyczne i wywołuje
się je ręcznie jednym kliknięciem w UI. To czyni je idealnym materiałem do
zbudowania i sprawdzenia całego toru — emisja, outbox, ponowienia, podpis,
dostarczenie. Detektor ataku jest trudny sam w sobie (stan, okna czasowe, fałszywe
trafienia) i debugowanie go równocześnie z niedziałającym torem to najgorszy
możliwy układ. Gdy tor działa, dołożenie detektora to napisanie jednej funkcji.

1. `domain/event` + katalog typów + `Publisher` zapisujący do `events`
2. tabele `events`, `subscriptions`, `deliveries` + repozytorium
3. worker: odczyt, wysyłka, backoff, oznaczanie
4. podpis HMAC + sink webhook `generic`
5. API i UI: zarządzanie subskrypcjami, historia dostarczeń
6. retencja i czyszczenie
7. detektory — dopiero teraz, i wyłącznie takie, które nie zależą od werdyktu
   (skanowanie portów, nowe urządzenie, ruch do podejrzanego portu, próg wolumenu,
   ruch poza godzinami). Reguły oparte na `packet.Action` nie mają sensu przed
   migracją z ADR 0004.

---

## Pytania otwarte

Nie blokują startu prac, ale trzeba je rozstrzygnąć zanim dotkną kodu, którego
dotyczą.

**Filtrowanie subskrypcji.** Czy wystarczy filtr po typie (`list.*`), czy chcemy
też po polach treści (`severity = "critical"`, `detector_id = "port-scan"`)?
To drugie jest wyraźnie użyteczniejsze, ale wymaga decyzji, jak zapisać filtr
i jak go wykonać. Wariant wystarczający w większości przypadków: kilka opcjonalnych
kolumn zamiast ogólnego języka zapytań.

**Historia dostarczeń w UI.** Czy użytkownik ma widzieć „wysłano, 200 OK, 14:32"
i przycisk „ponów"? Dane i tak są w `deliveries`, koszt to jeden endpoint i widok.

**Retencja.** Ile dni trzymamy `events`? Dotyczy żywotności karty SD i powinno być
ustalone przed pierwszym zapisem.

---

## Źródła

- [Standard Webhooks — specyfikacja](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)
- [CloudEvents — CNCF](https://cloudevents.io/)
- [Transactional Outbox: How to reliably generate webhook events — Convoy](https://www.getconvoy.io/blog/webhooks-with-transactional-outbox)
- [Implementing the Outbox pattern in Go — Panayiotis Kritiotis](https://pkritiotis.io/outbox-pattern-in-go/)
- [CloudEvents for Webhooks: Standard Envelope or Unnecessary Abstraction? — GetHook](https://gethook.to/blog/cloudevents-for-webhooks-standard-envelope)
