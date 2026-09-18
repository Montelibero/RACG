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

COPY gradlew gradlew
COPY gradle/wrapper gradle/wrapper
RUN chmod +x gradlew

COPY settings.gradle.kts settings.gradle.kts
COPY build.gradle.kts build.gradle.kts
COPY gradle.properties gradle.properties
COPY app/build.gradle.kts app/build.gradle.kts
COPY app/proguard-rules.pro app/proguard-rules.pro

RUN --mount=type=cache,target=/root/.gradle ./gradlew --no-daemon :app:dependencies >/dev/null

COPY app/src app/src

RUN --mount=type=cache,target=/root/.gradle ./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease

FROM scratch AS apk-export
COPY --from=build /workspace/app/build/outputs/apk/debug/app-debug.apk /racg-approver-debug.apk
COPY --from=build /workspace/app/build/outputs/apk/release/app-release-unsigned.apk /racg-approver-release-unsigned.apk

FROM android-sdk AS build-image
WORKDIR /workspace
COPY . .
CMD ["./gradlew", "--no-daemon", ":app:assembleDebug"]
