FROM adoptopenjdk:11-jre-hotspot

RUN addgroup --gid 1000 app; \
    adduser --disabled-password --gecos "" --home "$(pwd)" --ingroup app --no-create-home --uid 1000 app

ARG DEPENDENCY=./target/dependency
COPY ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY ${DEPENDENCY}/META-INF /app/META-INF
COPY ${DEPENDENCY}/BOOT-INF/classes /app

RUN mkdir /app-data

RUN chown -R app:app /app; \
    chown -R app:app /app-data

USER app

EXPOSE 8080

WORKDIR /app

ENV SIMPLE_AUTH_PORT="8080" \
    SIMPLE_AUTH_CONTEXT_PATH="/api" \
    SIMPLE_AUTH_LOG_LEVEL="debug" \
    SIMPLE_AUTH_DB_URL="jdbc:postgresql://localhost:5432/app" \
    SIMPLE_AUTH_DB_USER="app" \
    SIMPLE_AUTH_DB_PASS="app" \
    SIMPLE_AUTH_ISSUER="simple-auth" \
    SIMPLE_AUTH_EXPIRATION="1800" \
    SIMPLE_AUTH_PRIVATE_KEY="MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJtoXnsH6Ej7xpuRL9T1kElPWfH64KRjUQU6vRhgQi/z4FD6GncrK5PSjZA14XFiZZVeO6cvivdiQhpMBZqs9xjpiMmmAEBkEXf7MmvObsPuSa2jbLtXTGF8q5SZ83FIfFNwoghPToL9U64InhqBc2G6pbqisk38n14x/Y60/FSLAgMBAAECgYAXSxJ2QF4pqks/gAh6VAA3bMRfh6nqGdTIAuDa6XqiM1yY5pPW7sqOUo3TYrASzZvKQqCQU4jxwXGE/YYNhAVZI5GhUXS8l4m0QFjg7fe0pnLMq7uIUMgU0NUByv2fkZ1E5W/Z/7rJgABT4j56W9KAaJbmRUeYAUCyN7a55nktiQJBANhz5zc5KlWOJtmZ5kq1T7OKdv12JhMllAaL5ksxZk4Z6UUPXxudzTnK1/QyD2be7ySKjhsp6foM4kMPTbvEMyUCQQC3zTgKs29IizFjIvOt+rIESw4im+ojvz7bOFg6L02i+qbFNfMYuPB8Quq0ldR4t4Ujvb91UcjsYDMbfzd7ZLHvAkBAXueqMqP2YZoIKI6mNRmIyWrtoc9c7lYBRGWugvhrzaTj1thv/BPmVf63LpQKAc6YzWPJjEN7C43WZ5y0dHrJAkAwLeghzfU+w9XXUcMkeNGPFImJAuu2IRx95GAkKGAmd6OdkE2/zkKjn/rcCWZfmmOZAdUdEKolY/YhoBBQFQ4bAkAWwe3NoV1+OkJHVF+ECFUGmFfUgh3K5foGHkdrII82CnlSbflLb9ODPTS25XHHXz7ENzXAY2sFjih+lgJ+Mz8x" \
    SIMPLE_AUTH_PUBLIC_KEY="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCbaF57B+hI+8abkS/U9ZBJT1nx+uCkY1EFOr0YYEIv8+BQ+hp3KyuT0o2QNeFxYmWVXjunL4r3YkIaTAWarPcY6YjJpgBAZBF3+zJrzm7D7kmto2y7V0xhfKuUmfNxSHxTcKIIT06C/VOuCJ4agXNhuqW6orJN/J9eMf2OtPxUiwIDAQAB"

ENTRYPOINT ["java","-cp",".:lib/*","sk.janobono.SimpleAuthBackend"]
