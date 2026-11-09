# ------------------------------------------------------------------
# Этап 1: Сборка Native Image
# ------------------------------------------------------------------
FROM quay.io/quarkus/ubi-quarkus-mandrel-builder-image:jdk-25 AS build

WORKDIR /work

COPY --chown=1001:0 mvnw .
COPY --chown=1001:0 .mvn .mvn
COPY --chown=1001:0 pom.xml .

RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline -B

COPY --chown=1001:0 src src

RUN ./mvnw package -Pnative -Dquarkus.native.container-build=false -DskipTests
# ------------------------------------------------------------------
# Этап 2: Запуск приложения
# ------------------------------------------------------------------
FROM quay.io/quarkus/quarkus-micro-image:2.0

WORKDIR /work

COPY --from=build /work/target/*-runner /work/application

EXPOSE 8080

ENTRYPOINT ["/work/application"]
