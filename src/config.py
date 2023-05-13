#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of helper functions for getting configuration settings."""


def build_systemd_service():
    """Builds systemd service file contents."""
    service = """
        [Unit]
        Description=ui

        [Service]
        ExecStart=java -Dspring.config.additional-location=/tmp/application-local.yml --add-opens java.rmi/javax.rmi.ssl=ALL-UNNAMED -jar /tmp/ui.jar

        [Install]
        WantedBy=multi-user.target
    """

    return service


def build_application_local(
    username: str,
    password: str,
    bootstrap_server: str,
    security_protocol: str,
    truststore_password: str = "''",
    keystore_password: str = "''",
) -> str:
    """Builds application-local.yml file contents."""
    keystore_location = "/tmp/keystore.jks" if "SSL" in security_protocol else "''"
    truststore_location = "/tmp/truststore.jks" if "SSL" in security_protocol else "''"

    application_local = f"""
kafka:
  clusters:
    - name: charm
      bootstrapServers: {bootstrap_server}
      ssl:
        keystoreLocation: {keystore_location}
        keystorePassword: {keystore_password}
        truststoreLocation: {truststore_location}
        truststorePassword: {truststore_password}
      properties:
        security.protocol: {security_protocol}
        sasl.mechanism: SCRAM-SHA-512
        sasl.jaas.config: org.apache.kafka.common.security.scram.ScramLoginModule required username="{username}" password="{password}";
        ssl.endpoint.identification.algorithm: ''
        ssl.keystore.location: {keystore_location}
        ssl.keystore.password: {keystore_password}
        ssl.truststore.location: {truststore_location}
        ssl.truststore.password: {truststore_password}
    """

    return application_local
