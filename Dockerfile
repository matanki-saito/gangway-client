FROM openjdk:18-jdk-slim
VOLUME /tmp
ARG DEPENDENCY=target/dependency
COPY ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY ${DEPENDENCY}/META-INF /app/META-INF
COPY ${DEPENDENCY}/BOOT-INF/classes /app
RUN chmod +x app/docker-entrypoint.sh
RUN apt update && \
    apt-get -y install wget \
RUN KEYSTORE=$JAVA_HOME/lib/security/cacerts && \
    wget https://letsencrypt.org/certs/letsencryptauthorityx1.der && \
    wget https://letsencrypt.org/certs/letsencryptauthorityx2.der && \
    wget https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.der && \
    wget https://letsencrypt.org/certs/lets-encrypt-x2-cross-signed.der && \
    wget https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.der && \
    wget https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.der && \
    keytool -delete -alias isrgrootx1 -keystore $KEYSTORE -storepass changeit 2> /dev/null || true && \
    keytool -delete -alias isrgrootx2 -keystore $KEYSTORE -storepass changeit 2> /dev/null || true && \
    keytool -delete -alias letsencryptauthorityx1 -keystore $KEYSTORE -storepass changeit 2> /dev/null || true && \
    keytool -delete -alias letsencryptauthorityx2 -keystore $KEYSTORE -storepass changeit 2> /dev/null || true && \
    keytool -delete -alias letsencryptauthorityx3 -keystore $KEYSTORE -storepass changeit 2> /dev/null || true && \
    keytool -delete -alias letsencryptauthorityx4 -keystore $KEYSTORE -storepass changeit 2> /dev/null || true && \
    keytool -trustcacerts -keystore $KEYSTORE -storepass changeit -noprompt -importcert -alias isrgrootx1 -file letsencryptauthorityx1.der && \
    keytool -trustcacerts -keystore $KEYSTORE -storepass changeit -noprompt -importcert -alias isrgrootx2 -file letsencryptauthorityx2.der && \
    keytool -trustcacerts -keystore $KEYSTORE -storepass changeit -noprompt -importcert -alias letsencryptauthorityx1 -file lets-encrypt-x1-cross-signed.der && \
    keytool -trustcacerts -keystore $KEYSTORE -storepass changeit -noprompt -importcert -alias letsencryptauthorityx2 -file lets-encrypt-x2-cross-signed.der && \
    keytool -trustcacerts -keystore $KEYSTORE -storepass changeit -noprompt -importcert -alias letsencryptauthorityx3 -file lets-encrypt-x3-cross-signed.der && \
    keytool -trustcacerts -keystore $KEYSTORE -storepass changeit -noprompt -importcert -alias letsencryptauthorityx4 -file lets-encrypt-x4-cross-signed.der && \
    rm -f letsencryptauthorityx1.der letsencryptauthorityx2.der lets-encrypt-x1-cross-signed.der lets-encrypt-x2-cross-signed.der lets-encrypt-x3-cross-signed.der lets-encrypt-x4-cross-signed.der
ENTRYPOINT ["app/docker-entrypoint.sh"]
