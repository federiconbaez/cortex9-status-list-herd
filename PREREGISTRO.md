# Preregistro / Pre-registration

Escrito y commiteado antes de correr el barrido completo. Solo se corrió una
prueba de humo hasta 10^5 entradas para validar el binario; sus números no
se publican. / Written and committed before running the full sweep. Only a
smoke run up to 10^5 entries was made to validate the binary; its numbers are
not published.

## Criterio / Criterion (handoff)

> Barrido listas 10^3-10^7 y revocacion 0.1-10%: bytes zlib, tiempo de
> verificacion, frescura vs TTL, k-anonimato; CSV

## Diseño / Design

- Implementación / implementation: `affinidi-status-list` =0.1.7 (Apache-2.0), Token Status List draft-ietf-oauth-status-list-21, 1 bit por entrada. / 1 bit per entry.
- Tamaños / sizes: 10^3, 10^4, 10^5, 10^6, 10^7 entradas.
- Revocación / revocation: 0.1, 0.5, 1, 2, 5, 10 %; mínimo 1 revocada. / at least 1 revoked.
- Patrones / patterns: `random` (índices uniformes distintos) y `clustered` (ráfagas de 256 consecutivos). / uniform distinct indices and runs of 256 consecutive indices.
- 60 puntos; semillas fijas. / 60 points; fixed seeds.
- Bytes: arreglo crudo, zlib (nivel máximo del crate), `lst` base64url, JWT ES256 completo. / raw array, zlib (crate's best level), base64url `lst`, full ES256 JWT.
- Tiempo de verificación / verification time: `VerifiedStatusListToken::verify` (firma ES256, typ, sub, iat, exp, inflado) + `status_of`, 15 repeticiones, mediana y p90; además solo decodificación. Una máquina, un hilo, release. / 15 repetitions, median and p90; also decode only. One machine, one thread, release build.
- Frescura vs TTL / freshness vs TTL: modelo muestreado (200 000 muestras) con intervalo de emisión 300 s, 1 h, 24 h y ttl 60 s, 5 min, 1 h, 12 h, 24 h; política "fetch + ttl" de la sección 13.7. Se informa media, p50, p95, máximo y descargas por día. / sampled model, "fetch + ttl" policy from section 13.7; mean, p50, p95, max and fetches per day.
- k-anonimato / k-anonymity: `k_list` = entradas de la lista (privacidad de rebaño, sección 12.1) y `k_valid` = entradas no revocadas. Es un conteo, no un análisis formal. / entries in the list (herd privacy) and non-revoked entries. A count, not a formal analysis.

## Controles / Controls

- Positivos / positive: ejemplos de la sección 4 y vectores del Apéndice C (1, 2 y 4 bits) decodificados por el crate y por el decodificador de referencia; en cada punto del barrido, igualdad byte a byte, conteo de bits y lectura de cada índice revocado. / examples and Appendix C vectors; per sweep point, byte equality, popcount and every revoked index.
- Negativos / negative: firma alterada, payload cambiado, exp vencido, iat futuro, sub distinto, typ distinto, bits = 3, índice fuera de rango, sin status_list, lst inválido, bomba de inflado de 17 MiB. / all must be rejected.

## Hipótesis / Hypotheses

- H1: con revocación aleatoria, zlib crece con la tasa de revocación; con ráfagas, zlib queda muy por debajo del aleatorio a igual tasa.
- H2: a 10^7 entradas y 10 % aleatorio, el JWT supera 1 MB y la verificación sigue por debajo de 100 ms en esta máquina.
- H3: la obsolescencia máxima del modelo es ≤ intervalo + ttl, y la media ≈ (intervalo + ttl) / 2.

## Límites declarados / Declared limits

- Si 10^7 no entra en tiempo o memoria, se mide lo que entre y se declara. / If 10^7 does not fit, measure what fits and declare it.
- Sin red, sin despliegue real, sin análisis formal de privacidad. / No network, no real deployment, no formal privacy analysis.
