#!/usr/bin/env python3
# Copyright 2023 Canonical

"""Charm the service."""

import logging
import urllib.request
from typing import MutableMapping, Optional

from charms.data_platform_libs.v0.data_interfaces import KafkaRequires
from charms.operator_libs_linux.v0 import apt, systemd
from ops.charm import CharmBase, InstallEvent, RelationChangedEvent
from ops.main import main
from ops.model import ActiveStatus, Relation

from config import build_application_local, build_systemd_service
from tls import KafkaUiTLS
from utils import safe_write_to_file

logger = logging.getLogger(__name__)


class KafkaUiCharm(CharmBase):
    """Charmed Operator for KafkaUi."""

    def __init__(self, *args):
        super().__init__(*args)
        self.name = "kafka-ui"
        self.kafka_requires = KafkaRequires(
            self, relation_name="kafka-client", topic="default", extra_user_roles="admin"
        )
        self.tls = KafkaUiTLS(self)

        self.framework.observe(getattr(self.on, "install"), self._on_install)
        self.framework.observe(
            getattr(self.kafka_requires.on, "topic_created"), self._topic_created
        )

    @property
    def peer_relation(self) -> Optional[Relation]:
        """The cluster peer relation."""
        return self.model.get_relation("cluster")

    @property
    def app_peer_data(self) -> MutableMapping[str, str]:
        """Application peer relation data object."""
        if not self.peer_relation:
            return {}

        return self.peer_relation.data[self.app]

    @property
    def unit_peer_data(self) -> MutableMapping[str, str]:
        """Unit peer relation data object."""
        if not self.peer_relation:
            return {}

        return self.peer_relation.data[self.unit]

    @property
    def unit_host(self) -> str:
        """Return the own host."""
        return self.unit_peer_data.get("private-address", "")

    def _on_install(self, _: InstallEvent):
        apt.update()
        apt.add_package(["openjdk-17-jre-headless"])
        jar = urllib.request.urlopen(
            "https://github.com/provectus/kafka-ui/releases/download/v0.7.0/kafka-ui-api-v0.7.0.jar"
        ).read()
        safe_write_to_file(content=jar, path="/tmp/ui.jar", mode="wb")

        systemd_service = build_systemd_service()
        safe_write_to_file(content=systemd_service, path="/etc/systemd/system/ui.service")

    def _topic_created(self, event: RelationChangedEvent):
        if not event.relation or not event.app:
            return

        username = event.relation.data[event.app].get("username", "")
        password = event.relation.data[event.app].get("password", "")
        bootstrap_server = event.relation.data[event.app].get("endpoints", "")

        if not all([username, password, bootstrap_server]):
            event.defer()
            return

        security_protocol = (
            "SASL_SSL"
            if event.relation.data[event.app].get("tls", "") == "enabled"
            else "SASL_PLAINTEXT"
        )

        application_local = build_application_local(
            username=username,
            password=password,
            bootstrap_server=bootstrap_server,
            security_protocol=security_protocol,
            keystore_password=self.tls.keystore_password or "''",
            truststore_password=self.tls.truststore_password or "''",
        )

        safe_write_to_file(content=application_local, path="/tmp/application-local.yml")

        systemd.daemon_reload()
        systemd.service_start("ui.service")

        self.unit.status = ActiveStatus()

    def get_secret(self, scope: str, key: str) -> Optional[str]:
        """Get TLS secret from the secret storage.

        Args:
            scope: whether this secret is for a `unit` or `app`
            key: the secret key name

        Returns:
            String of key value.
            None if non-existent key
        """
        if scope == "unit":
            return self.unit_peer_data.get(key, None)
        elif scope == "app":
            return self.app_peer_data.get(key, None)
        else:
            raise RuntimeError("Unknown secret scope.")

    def set_secret(self, scope: str, key: str, value: Optional[str]) -> None:
        """Get TLS secret from the secret storage.

        Args:
            scope: whether this secret is for a `unit` or `app`
            key: the secret key name
            value: the value for the secret key
        """
        if scope == "unit":
            if not value:
                self.unit_peer_data.update({key: ""})
                return
            self.unit_peer_data.update({key: value})
        elif scope == "app":
            if not value:
                self.app_peer_data.update({key: ""})
                return
            self.app_peer_data.update({key: value})
        else:
            raise RuntimeError("Unknown secret scope.")


if __name__ == "__main__":
    main(KafkaUiCharm)
