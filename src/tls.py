"""Manager for handling KafkaUI TLS configuration."""

import logging
import socket
from typing import TYPE_CHECKING, Optional

from charms.operator_libs_linux.v0.apt import subprocess
from ops.framework import Object
from ops.model import Relation

from utils import generate_password, safe_write_to_file

if TYPE_CHECKING:
    from charm import KafkaUiCharm


from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequiresV1,
    generate_csr,
    generate_private_key,
)

logger = logging.getLogger(__name__)


class KafkaUiTLS(Object):
    """Handler for managing the client and unit TLS keys/certs."""

    def __init__(self, charm):
        super().__init__(charm, "tls")
        self.charm: "KafkaUiCharm" = charm
        self.certificates = TLSCertificatesRequiresV1(self.charm, "certificates")

        self.framework.observe(
            self.charm.on["certificates"].relation_created, self._tls_relation_created
        )
        self.framework.observe(
            self.charm.on["certificates"].relation_joined, self._tls_relation_joined
        )

        self.framework.observe(
            getattr(self.certificates.on, "certificate_available"), self._on_certificate_available
        )

    @property
    def peer_relation(self) -> Optional[Relation]:
        """Get the peer relation of the charm."""
        return self.charm.peer_relation

    @property
    def enabled(self) -> bool:
        """Flag to check if the cluster should run with TLS.

        Returns:
            True if TLS encryption should be active. Otherwise False
        """
        return self.charm.app_peer_data.get("tls", "disabled") == "enabled"

    @property
    def private_key(self) -> Optional[str]:
        """The unit private-key set during `certificates_joined`.

        Returns:
            String of key contents
            None if key not yet generated
        """
        return self.charm.get_secret(scope="unit", key="private-key")

    @property
    def csr(self) -> Optional[str]:
        """The unit cert signing request.

        Returns:
            String of csr contents
            None if csr not yet generated
        """
        return self.charm.get_secret(scope="unit", key="csr")

    @property
    def certificate(self) -> Optional[str]:
        """The signed unit certificate from the provider relation.

        Returns:
            String of cert contents in PEM format
            None if cert not yet generated/signed
        """
        return self.charm.get_secret(scope="unit", key="certificate")

    @property
    def ca(self) -> Optional[str]:
        """The ca used to sign unit cert.

        Returns:
            String of ca contents in PEM format
            None if cert not yet generated/signed
        """
        return self.charm.get_secret(scope="unit", key="ca")

    @property
    def keystore_password(self) -> Optional[str]:
        """The unit keystore password set during `certificates_joined`.

        Returns:
            String of password
            None if password not yet generated
        """
        return self.charm.get_secret(scope="unit", key="keystore-password")

    @property
    def truststore_password(self) -> Optional[str]:
        """The unit truststore password set during `certificates_joined`.

        Returns:
            String of password
            None if password not yet generated
        """
        return self.charm.get_secret(scope="unit", key="truststore-password")

    def _tls_relation_created(self, _) -> None:
        """Handler for `certificates_relation_created` event."""
        if not self.charm.unit.is_leader() or not self.peer_relation:
            return

        self.peer_relation.data[self.charm.app].update({"tls": "enabled"})

    def _tls_relation_joined(self, _) -> None:
        """Handler for `certificates_relation_joined` event."""
        # generate unit private key if not already created by action
        if not self.private_key:
            self.charm.set_secret(
                scope="unit", key="private-key", value=generate_private_key().decode("utf-8")
            )

        logger.info(f"{self.private_key=}")

        # generate unit private key if not already created by action
        if not self.keystore_password:
            self.charm.set_secret(scope="unit", key="keystore-password", value=generate_password())
            logger.info(f"{self.keystore_password=}")
        if not self.truststore_password:
            self.charm.set_secret(
                scope="unit", key="truststore-password", value=generate_password()
            )
            logger.info(f"{self.truststore_password=}")

        self._request_certificate()

    def _request_certificate(self):
        """Generates and submits CSR to provider."""
        if not self.private_key or not self.peer_relation:
            logger.error("Can't request certificate, missing private key")
            return

        logger.info(f"{self._sans=}")
        logger.info(f'{self.peer_relation.data[self.charm.unit].get("private-address", "")=}')

        csr = generate_csr(
            private_key=self.private_key.encode("utf-8"),
            subject=self.peer_relation.data[self.charm.unit].get("private-address", ""),
            **self._sans,
        )
        self.charm.set_secret(scope="unit", key="csr", value=csr.decode("utf-8").strip())

        self.certificates.request_certificate_creation(certificate_signing_request=csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handler for `certificates_available` event after provider updates signed certs."""
        if not self.peer_relation:
            logger.warning("No peer relation on certificate available")
            event.defer()
            return

        # avoid setting tls files and restarting
        if event.certificate_signing_request != self.csr:
            logger.error("Can't use certificate, found unknown CSR")
            return

        self.charm.set_secret(scope="unit", key="certificate", value=event.certificate)
        self.charm.set_secret(scope="unit", key="ca", value=event.ca)

        self.set_server_key()
        self.set_ca()
        self.set_certificate()
        self.set_truststore()
        self.set_keystore()

    def generate_alias(self, app_name: str, relation_id: int) -> str:
        """Generate an alias from a relation. Used to identify ca certs."""
        return f"{app_name}-{relation_id}"

    def set_server_key(self) -> None:
        """Sets the unit private-key."""
        if not self.private_key:
            logger.error("Can't set private-key to unit, missing private-key in relation data")
            return

        safe_write_to_file(content=self.private_key, path="/tmp/server.key")

    def set_ca(self) -> None:
        """Sets the unit ca."""
        if not self.ca:
            logger.error("Can't set CA to unit, missing CA in relation data")
            return

        safe_write_to_file(content=self.ca, path="/tmp/ca.pem")

    def set_certificate(self) -> None:
        """Sets the unit certificate."""
        if not self.certificate:
            logger.error("Can't set certificate to unit, missing certificate in relation data")
            return

        safe_write_to_file(content=self.certificate, path="/tmp/server.pem")

    def set_truststore(self) -> None:
        """Adds CA to JKS truststore."""
        try:
            subprocess.check_output(
                f"keytool -import -v -alias ca -file ca.pem -keystore truststore.jks -storepass {self.truststore_password} -noprompt",
                stderr=subprocess.PIPE,
                shell=True,
                universal_newlines=True,
                cwd="/tmp",
            )
        except subprocess.CalledProcessError as e:
            # in case this reruns and fails
            if "already exists" in e.output:
                return
            logger.error(e.output)
            raise e

    def set_keystore(self) -> None:
        """Creates and adds unit cert and private-key to the keystore."""
        try:
            subprocess.check_output(
                f"openssl pkcs12 -export -in server.pem -inkey server.key -passin pass:{self.keystore_password} -certfile server.pem -out keystore.p12 -password pass:{self.keystore_password}",
                stderr=subprocess.PIPE,
                shell=True,
                universal_newlines=True,
                cwd="/tmp",
            )
            subprocess.check_output(
                f"keytool -importkeystore -destkeystore keystore.jks -deststoretype jks -deststorepass {self.keystore_password} -srckeystore keystore.p12 -srcstoretype pkcs12 -srcstorepass {self.keystore_password} -noprompt",
                stderr=subprocess.PIPE,
                shell=True,
                universal_newlines=True,
                cwd="/tmp",
            )
        except subprocess.CalledProcessError as e:
            logger.error(e.output)
            raise e

    def import_cert(self, alias: str, filename: str) -> None:
        """Add a certificate to the truststore."""
        try:
            subprocess.check_output(
                f"keytool -import -v -alias {alias} -file {filename} -keystore truststore.jks -storepass {self.truststore_password} -noprompt",
                stderr=subprocess.PIPE,
                shell=True,
                universal_newlines=True,
                cwd="/tmp",
            )
        except subprocess.CalledProcessError as e:
            # in case this reruns and fails
            if "already exists" in e.output:
                logger.warning(e.output)
                return
            logger.error(e.output)
            raise e

    @property
    def _sans(self) -> dict[str, list[str]]:
        """Builds a SAN dict of DNS names and IPs for the unit."""
        return {
            "sans_ip": [self.charm.unit_host],
            "sans_dns": [self.charm.unit.name, socket.getfqdn()],
        }
