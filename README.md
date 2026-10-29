# status-list-herd

Barrido de costo y privacidad de rebaño de Token Status List ([draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt)) con el crate [`affinidi-status-list`](https://crates.io/crates/affinidi-status-list) 0.1.7: listas de 10^3 a 10^7 entradas y revocación de 0.1 % a 10 %, firmadas como `statuslist+jwt` ES256 y verificadas por el crate.

Cost and herd-privacy sweep of Token Status List (draft-21) using `affinidi-status-list` 0.1.7: lists of 10^3 to 10^7 entries with 0.1 % to 10 % revocation, signed as ES256 `statuslist+jwt` and verified by the crate.

> **ES** primero · **EN** abajo. Nivel de verificación: **B**.

---

## ES

### Qué se mide

- 60 puntos: 5 tamaños (10^3 … 10^7) × 6 tasas (0.1, 0.5, 1, 2, 5, 10 %) × 2 patrones (`random`: índices uniformes; `clustered`: ráfagas de 256 consecutivos). 1 bit por entrada, semillas fijas.
- Bytes: arreglo crudo, zlib (nivel máximo, como recomienda §4.1), `lst` base64url y JWT ES256 completo.
- Tiempo de verificación: `VerifiedStatusListToken::verify` (firma ES256, `typ`, `sub`, `iat`, `exp`, inflado con tope) más `status_of`; 15 repeticiones, mediana y p90; aparte, solo decodificación.
- Frescura vs `ttl`: modelo muestreado (200 000 muestras) de la política "fetch + ttl" de §13.7, con intervalos de emisión de 5 min, 1 h y 24 h.
- k: `k_list` = entradas de la lista (privacidad de rebaño de §12.1) y `k_valid` = entradas no revocadas.
- Diseño y umbrales fijados antes de medir en [`PREREGISTRO.md`](PREREGISTRO.md).

Reproducir: `cargo run --release --bin status-list-herd -- --reps 15 --out results` (5.4 s en la máquina de [`results/ENTORNO.md`](results/ENTORNO.md)).

### Resultados

Archivos: [`results/sweep.csv`](results/sweep.csv) (todo), [`results/sizes.csv`](results/sizes.csv) (solo bytes y k, determinista; CI lo regenera y exige que sea idéntico) y [`results/freshness.csv`](results/freshness.csv).

Extremos medidos (10 % de revocación):

| Entradas | Patrón | zlib (B) | JWT (B) | Verificación mediana / p90 (ms) | Solo decodificar (ms) |
|---|---|---|---|---|---|
| 10^3 | random | 101 | 507 | 0.334 / 0.339 | 0.005 |
| 10^5 | random | 7 120 | 12 986 | 0.405 / 0.559 | 0.052 |
| 10^6 | random | 69 843 | 124 493 | 1.077 / 1.303 | 0.615 |
| 10^7 | random | 693 885 | 1 233 901 | 7.521 / 13.887 | 5.974 |
| 10^7 | clustered | 7 661 | 13 947 | 0.590 / 0.708 | 0.241 |
| 10^7 | random, 0.1 % | 25 537 | 45 727 | 0.794 / 0.888 | 0.408 |

- Con revocación aleatoria zlib crece con la tasa en los 5 tamaños. Con ráfagas, el tamaño cae a entre 1.1 % y 5.4 % del aleatorio a 10^7.
- El JWT ocupa unas 1.78 veces lo que ocupa zlib: `lst` va en base64url dentro del JSON y el payload completo vuelve a ir en base64url en el JWS.
- La firma ES256 marca un piso de unos 0.33 ms; por debajo de 10^5 entradas el tamaño de la lista casi no cambia el tiempo.

Frescura (modelo, no despliegue): en las 15 combinaciones la obsolescencia máxima quedó por debajo de intervalo + ttl, y la media se desvió como mucho 0.12 % de (intervalo + ttl) / 2. Ejemplo: con emisión cada 1 h y `ttl` de 12 h (el ejemplo del draft usa 43200 s), la media fue 23 374 s (6.5 h), el p95 fue 42 844 s y hubo 2 descargas por día por cliente.

### Controles

- Positivos: ejemplos de §4.1/§4.2 y vectores del Apéndice C de 1, 2 y 4 bits (2^20 entradas, cada índice comparado) los decodifican igual el crate y el decodificador de referencia, escrito aparte desde §4. En los 60 puntos, el decodificador de referencia coincide byte a byte, cuenta exactamente los bits revocados y lee 1 en cada índice revocado; el crate devuelve `INVALID` para un índice revocado y `VALID` para uno que no lo está.
- Negativos (todos rechazados por el crate): firma alterada, payload cambiado bajo la misma firma, `exp` vencido, `iat` futuro, `sub` distinto, `typ` distinto, `bits` = 3, índice fuera de rango, sin `status_list`, `lst` inválido y bomba de inflado de 17 MiB comprimida a menos de 64 KiB.

#### Qué prueba y qué no el 60/60 y el 11/11

- **Prueba**: en esta grilla y con estas semillas, el codificador del crate y un decodificador independiente escrito desde el texto del draft coinciden en cada byte, y la verificación del crate rechaza esas 11 alteraciones concretas.
- **No prueba**: que el crate sea correcto con 2, 4 u 8 bits en listas propias (eso solo se cubre con los vectores del Apéndice C), con otros algoritmos de firma, con CWT o con claves que haya que resolver (§11.3). Tampoco cubre alteraciones fuera de esa lista de 11, ni compromiso de clave, ni repetición de un token viejo todavía vigente, ni el comportamiento ante un servidor real. La grilla y los controles son nuestros: un 100 % sobre un corpus propio indica consistencia, no ausencia de errores.

### Hallazgos sobre el crate (observaciones, sin reportar)

- `ttl` = 0 se acepta, aunque §5.1 dice que "MUST be a positive number".
- `ttl` = 43200.5 se rechaza: el crate exige un entero, mientras que el draft solo pide un número positivo.
- Sin `exp` ni `ttl` el token se acepta, lo que es correcto: los dos son RECOMMENDED.
- El tope de inflado por defecto es de 16 MiB, así que a 1 bit entran listas de hasta unos 134 millones de entradas.

### Criterios de aceptación (handoff)

| Criterio | Estado |
|---|---|
| Barrido de listas 10^3–10^7 | **Cumplido**: los 5 tamaños, 10^7 incluido, entran en memoria y tiempo |
| Revocación 0.1–10 % | **Cumplido**: 6 tasas × 2 patrones |
| Bytes zlib | **Cumplido** |
| Tiempo de verificación | **Cumplido**: en una máquina y un hilo |
| Frescura vs TTL | **Cumplido como modelo**: muestreado y sin red ni despliegue real |
| k-anonimato | **Parcial**: solo conteo (`k_list`, `k_valid`); sin análisis formal, que el handoff deja fuera de alcance |
| CSV | **Cumplido** |

Hipótesis del preregistro:

- **H1**: se cumple con una excepción. Con 10^3 entradas y 0.1 % hay una sola revocada, y los dos patrones dan el mismo tamaño (24 B).
- **H2**: se cumple. El JWT pesa 1 233 901 B y la verificación tarda 7.5 ms de mediana y 13.9 ms de p90.
- **H3**: se cumple.

### Nivel de verificación

- **A**: compila; `fmt`, `clippy -D warnings` y 11/11 tests en verde, sin ningún test ignorado.
- **B**: medición prerregistrada, con controles positivos (vectores del draft) y negativos. Los bytes son deterministas y CI los regenera y los compara.
- No llega a B+ ni a C: los tiempos salen de una sola máquina virtual, no hay línea base contra otra implementación y no hubo uso real.

### Límites

- Solo 1 bit por entrada en el barrido, solo JWT (sin CWT), solo ES256 con una clave fija de prueba.
- Los tiempos no incluyen red, TLS ni resolución de clave. La p90 a 10^7 muestra ruido de la máquina virtual.
- El modelo de frescura supone demora de red y de firma igual a cero, y un cliente que verifica de forma continua.
- `bh-status-list` no se usó porque su licencia es AGPL-3.0 y este repo es Apache-2.0.
- Los hallazgos no se reportaron al mantenedor; esa decisión le queda a Federico.

### Fuentes leídas

- draft-ietf-oauth-status-list-21: §4, §4.1, §4.2, §5.1, §8.1–§8.3, §11.5, §12.1–§12.5, §13.4, §13.7 y el Apéndice C — <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt>
- `affinidi-status-list` 0.1.7: metadatos de crates.io, README, `src/lib.rs` y `src/token.rs`.
- `bh-status-list` 0.3.0: metadatos de crates.io y `COPYING` (AGPL-3.0); el código no se usó.

---

## EN

**What:** 60 points (10^3–10^7 entries × 0.1–10 % revocation × random/clustered) of 1-bit Token Status Lists built and verified with `affinidi-status-list` 0.1.7. For each point the sweep records raw, zlib, `lst` and full ES256 JWT bytes, plus verification time (crate `verify` + `status_of`, 15 reps, median/p90) and decode-only time. Freshness vs `ttl` comes from a sampled model of the §13.7 "fetch + ttl" policy, and k is reported as list size and non-revoked count. Everything was pre-registered in `PREREGISTRO.md`.

**Results:** see `results/sweep.csv`, `results/sizes.csv` (deterministic; CI re-runs it and diffs it) and `results/freshness.csv`.
- At 10^7 entries and 10 % random revocation: zlib 693 885 B, JWT 1 233 901 B, verification 7.5 ms median and 13.9 ms p90.
- Clustered revocation at 10^7 shrinks the list to 1.1–5.4 % of the random size.
- The JWT is about 1.78× zlib because of the double base64url.
- The ES256 floor is about 0.33 ms.
- Modelled staleness: the maximum stayed within update + ttl in all 15 combinations, and the mean was within 0.12 % of (update + ttl)/2.

**Controls:**
- The draft §4 examples and the Appendix C vectors (1/2/4-bit) decode identically in the crate and in an independent reference decoder.
- In all 60 points the reference matches byte for byte, matches the popcount and reads every revoked index.
- 11 tampered or invalid tokens are all rejected.

**What 60/60 and 11/11 prove and don't:**
- **They prove** byte-level agreement between the crate's encoder and an independent decoder written from the draft, on this grid with these seeds, and that the crate rejects those 11 specific alterations.
- **They don't cover** 2/4/8-bit lists beyond the Appendix C vectors, other algorithms, CWT, key resolution (§11.3), alterations outside the 11, key compromise, replay of an old but unexpired token, or a live server.
- The grid and controls are ours. 100 % on our own corpus shows consistency, not absence of bugs.

**Observations on the crate (not reported upstream):**
- It accepts `ttl` = 0 although §5.1 requires a positive number.
- It rejects the non-integer `ttl` 43200.5.
- Its default inflate cap is 16 MiB.

**Acceptance criteria:**
- Met: sizes 10^3–10^7 (including 10^7), revocation 0.1–10 %, zlib bytes, verification time and CSV.
- Freshness: met as a model only.
- k-anonymity: partial, counts only; a formal analysis is out of scope.
- Hypotheses: H1 holds except at 10^3 entries and 0.1 % (one revoked entry; both patterns give 24 B). H2 and H3 hold.

**Verification level: B.**
- Pre-registered, deterministic sizes checked in CI, positive and negative controls.
- Not B+/C: timings come from one VM, with no baseline implementation and no real use.

**Limits:**
- 1-bit lists, JWT only and ES256 with a fixed test key.
- No network, TLS or key resolution in the timings.
- The freshness model assumes zero network and signing delay.
- `bh-status-list` was not used (AGPL-3.0).

## License

Apache-2.0
