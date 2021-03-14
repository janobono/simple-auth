FROM adoptopenjdk:15-jre-openj9

RUN addgroup --gid 1000 app; \
    adduser --disabled-password --gecos "" --home "$(pwd)" --ingroup app --no-create-home --uid 1000 app

ARG DEPENDENCY=./target/dependency
COPY ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY ${DEPENDENCY}/META-INF /app/META-INF
COPY ${DEPENDENCY}/BOOT-INF/classes /app

RUN chown -R app:app /app

USER app

EXPOSE 8080

WORKDIR /app

ENTRYPOINT ["java","-cp",".:lib/*","sk.janobono.SimpleAuthBackend"]
