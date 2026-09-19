# syntax=docker/dockerfile:1.7
FROM eclipse-temurin:17-jdk-jammy AS android-sdk

ARG ANDROID_CMDLINE_TOOLS_VERSION=11076708
ARG ANDROID_PLATFORM=android-35
ARG ANDROID_BUILD_TOOLS=35.0.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV ANDROID_HOME=/opt/android-sdk
ENV PATH="${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${PATH}"

RUN mkdir -p "${ANDROID_HOME}/cmdline-tools" \
    && curl -fsSL "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_VERSION}_latest.zip" -o /tmp/tools.zip \
    && unzip -q /tmp/tools.zip -d "${ANDROID_HOME}/cmdline-tools" \
    && mv "${ANDROID_HOME}/cmdline-tools/cmdline-tools" "${ANDROID_HOME}/cmdline-tools/latest" \
    && rm /tmp/tools.zip

RUN yes | sdkmanager --licenses >/dev/null \
    && sdkmanager "platform-tools" "platforms;${ANDROID_PLATFORM}" "build-tools;${ANDROID_BUILD_TOOLS}" >/dev/null

FROM android-sdk AS build
WORKDIR /workspace
ARG SOURCE_REVISION=local
ARG ANDROID_VERSION_CODE=2
ARG ANDROID_VERSION_NAME=0.1.0-alpha.1
ENV RACG_ANDROID_VERSION_CODE=${ANDROID_VERSION_CODE}
ENV RACG_ANDROID_VERSION_NAME=${ANDROID_VERSION_NAME}

COPY gradlew gradlew
COPY gradle/wrapper gradle/wrapper
RUN chmod +x gradlew

COPY settings.gradle.kts settings.gradle.kts
COPY build.gradle.kts build.gradle.kts
COPY gradle.properties gradle.properties
COPY docker/debug.keystore docker/debug.keystore
COPY app/build.gradle.kts app/build.gradle.kts
COPY app/proguard-rules.pro app/proguard-rules.pro

RUN --mount=type=cache,target=/root/.gradle ./gradlew --no-daemon :app:dependencies >/dev/null

COPY app/src app/src

RUN --mount=type=cache,target=/root/.gradle \
    --mount=type=secret,id=racg_release_keystore,target=/run/secrets/release.keystore \
    --mount=type=secret,id=racg_release_properties,target=/run/secrets/release.properties \
    if [ -f /run/secrets/release.keystore ] && [ -f /run/secrets/release.properties ]; then \
      export RACG_RELEASE_STORE=/run/secrets/release.keystore; \
      set -a; \
      . /run/secrets/release.properties; \
      set +a; \
    fi; \
    export RACG_SOURCE_REVISION="$SOURCE_REVISION"; \
    ./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease \
    && mkdir /out \
    && cp app/build/outputs/apk/debug/app-debug.apk /out/racg-approver-debug.apk \
    && if [ -f app/build/outputs/apk/release/app-release.apk ]; then \
      cp app/build/outputs/apk/release/app-release.apk /out/racg-approver-release.apk; \
    else \
      cp app/build/outputs/apk/release/app-release-unsigned.apk /out/racg-approver-release-unsigned.apk; \
    fi

FROM scratch AS apk-export
COPY --from=build /workspace/app/build/outputs/apk/debug/app-debug.apk /racg-approver-debug.apk
COPY --from=build /out/ ./

FROM android-sdk AS build-image
WORKDIR /workspace
COPY . .
CMD ["./gradlew", "--no-daemon", ":app:assembleDebug"]
