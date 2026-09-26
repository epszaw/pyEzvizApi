"""Ezviz cloud MQTT client for push messages.

Synchronous MQTT client tailored for EZVIZ push notifications as used by
`pyezvizapi` and Home Assistant integrations. Handles the EZVIZ registration
flow, starts/stops push, maintains a long-lived MQTT connection, and decodes
incoming payloads into a structured form.

This module is intentionally synchronous (uses `requests` and
`paho-mqtt`'s background network thread via `loop_start()`), which keeps
integration code simple. If you later migrate to an async HA integration,
wrap the blocking calls with `hass.async_add_executor_job`.

Example:
    >>> client = MQTTClient(token)
    >>> client.connect()
    >>> # ... handle callbacks or read client.messages_by_device ...
    >>> client.stop()

"""

from __future__ import annotations

import base64
from collections import OrderedDict
from collections.abc import Callable, Collection
from contextlib import suppress
from dataclasses import dataclass
import json
import logging
import ssl
from threading import RLock
import time
from typing import Any, Final, TypedDict

import paho.mqtt.client as mqtt
import requests

from .api_endpoints import (
    API_ENDPOINT_REGISTER_MQTT,
    API_ENDPOINT_START_MQTT,
    API_ENDPOINT_STOP_MQTT,
)
from .constants import APP_SECRET, DEFAULT_TIMEOUT, FEATURE_CODE, MQTT_APP_KEY
from .exceptions import HTTPError, InvalidURL, PyEzvizError

_LOGGER = logging.getLogger(__name__)

DEFAULT_MAX_PAYLOAD_SIZE: Final = 256 * 1024
DEFAULT_MAX_JSON_NESTING: Final = 64
DEFAULT_DEDUPLICATION_CACHE_SIZE: Final = 2048
DEFAULT_MQTT_PORT: Final = 1882


# ---------------------------------------------------------------------------
# Typed structures
# ---------------------------------------------------------------------------


class ServiceUrls(TypedDict):
    """Service URLs present in the EZVIZ auth token.

    Attributes:
        pushAddr: Hostname of the EZVIZ push/MQTT entry point.
    """

    pushAddr: str


class EzvizToken(TypedDict):
    """Minimal shape of the EZVIZ token required for MQTT.

    Attributes:
        username: Internal EZVIZ username.
        session_id: Current session id.
        service_urls: Nested object containing at least ``pushAddr``.
    """

    username: str
    session_id: str
    service_urls: ServiceUrls


class MqttData(TypedDict):
    """Typed dictionary for EZVIZ MQTT connection data."""

    mqtt_clientid: str | None
    ticket: str | None
    push_url: str


@dataclass(frozen=True)
class MqttMessagePolicy:
    """Validation and filtering policy for incoming MQTT messages."""

    max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE
    max_json_nesting: int = DEFAULT_MAX_JSON_NESTING
    allowed_device_serials: Collection[str] | None = None
    allowed_alert_types: Collection[int] | None = None
    deduplicate_messages: bool = False
    deduplication_cache_size: int = DEFAULT_DEDUPLICATION_CACHE_SIZE

    def __post_init__(self) -> None:
        if self.max_payload_size < 1:
            raise ValueError("max_payload_size must be greater than zero")
        if self.max_json_nesting < 1:
            raise ValueError("max_json_nesting must be greater than zero")
        if self.deduplication_cache_size < 1:
            raise ValueError("deduplication_cache_size must be greater than zero")
        if self.allowed_device_serials is not None:
            object.__setattr__(
                self,
                "allowed_device_serials",
                frozenset(str(serial) for serial in self.allowed_device_serials),
            )
        if self.allowed_alert_types is not None:
            object.__setattr__(
                self,
                "allowed_alert_types",
                frozenset(int(alert_type) for alert_type in self.allowed_alert_types),
            )


@dataclass(frozen=True)
class MqttTransportConfig:
    """MQTT broker transport settings with optional strict TLS."""

    port: int = DEFAULT_MQTT_PORT
    use_tls: bool = False
    tls_context: ssl.SSLContext | None = None

    def __post_init__(self) -> None:
        if self.port < 1 or self.port > 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.tls_context is not None and not self.use_tls:
            raise ValueError("tls_context requires use_tls=True")
        if self.tls_context is not None and (
            not self.tls_context.check_hostname
            or self.tls_context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise ValueError(
                "tls_context must require certificate and hostname verification"
            )


# ---------------------------------------------------------------------------
# Payload decoding helpers
# ---------------------------------------------------------------------------

# Field names in the comma-separated ``ext`` payload from EZVIZ.
EXT_FIELD_NAMES: Final[tuple[str, ...]] = (
    "channel_type",
    "time",
    "device_serial",
    "channel_no",
    "alert_type_code",
    "default_pic_url",
    "media_url_alt1",
    "media_url_alt2",
    "resource_type",
    "status_flag",
    "file_id",
    "is_encrypted",
    "picChecksum",
    "is_dev_video",
    "metadata",
    "msgId",
    "image",
    "device_name",
    "reserved",
    "sequence_number",
)

# Fields that should be converted to ``int`` if present.
EXT_INT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "channel_type",
        "channel_no",
        "alert_type_code",
        "resource_type",
        "status_flag",
        "is_encrypted",
        "is_dev_video",
        "sequence_number",
    }
)


def _validate_json_nesting(payload: bytes, *, maximum: int) -> None:
    """Reject excessive JSON object/array nesting before parser recursion."""

    depth = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in (ord("{"), ord("[")):
            depth += 1
            if depth > maximum:
                raise PyEzvizError(
                    "Unable to decode MQTT message: "
                    f"JSON nesting exceeds maximum depth {maximum}"
                )
        elif byte in (ord("}"), ord("]")):
            depth = max(0, depth - 1)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class MQTTClient:
    """MQTT client for Ezviz push notifications.

    Handles the Ezviz-specific registration and connection process,
    maintains a persistent MQTT connection, and processes incoming messages.

    Messages are stored per device_serial in `messages_by_device`, and an optional
    callback can be provided to handle messages as they arrive.

    Typical usage::

        client = MQTTClient(token=auth_token)
        client.connect(clean_session=True)

        # Access last message for a device
        last_msg = client.messages_by_device.get(device_serial)

        # Stop the client when done
        client.stop()
    """

    def __init__(
        self,
        token: EzvizToken | dict,
        session: requests.Session,
        timeout: int = DEFAULT_TIMEOUT,
        on_message_callback: Callable[[dict[str, Any]], None] | None = None,
        *,
        max_messages: int = 1000,
        message_policy: MqttMessagePolicy | None = None,
        transport: MqttTransportConfig | None = None,
    ) -> None:
        """Initialize the Ezviz MQTT client.

        This client handles registration with the Ezviz push service, maintains
        a persistent MQTT connection, and decodes incoming push messages.

        Args:
            token (dict): Authentication token dictionary returned by EzvizClient.login().
                Must include:
                    - 'username': Ezviz account username (The account aliase or generated one.)
                    - 'session_id': session token for API access
                    - 'service_urls': dictionary containing at least 'pushAddr'
            timeout (int, optional): HTTP request timeout in seconds. Defaults to DEFAULT_TIMEOUT.
            session (requests.Session): Pre-configured requests session for HTTP calls.
            on_message_callback (Callable[[dict[str, Any]], None], optional): Optional callback function
                that will be called for each decoded MQTT message. The callback receives
                a dictionary with the message data. Defaults to None.
            max_messages:
                Maximum number of device entries kept in :attr:`messages_by_device`.
                Oldest entries are evicted when the limit is exceeded. Defaults to ``1000``.
            message_policy:
                Optional payload size, allowlist, and deduplication policy.
            transport:
                Optional broker port and strict TLS configuration.

        Raises:
            PyEzvizError: If the provided token is missing required fields.
        """
        if not token or not token.get("username"):
            raise PyEzvizError(
                "Ezviz internal username is required. Ensure EzvizClient.login() was called first."
            )
        if max_messages < 1:
            raise ValueError("max_messages must be greater than zero")

        # Requests session (synchronous)
        self._session = session

        self._token: EzvizToken | dict = token
        self._timeout: int = timeout
        self._topic: str = f"{MQTT_APP_KEY}/#"
        self._on_message_callback = on_message_callback
        self._max_messages: int = max_messages
        self._message_policy = message_policy or MqttMessagePolicy()
        self._transport = transport or MqttTransportConfig()
        self._seen_message_ids: OrderedDict[tuple[str, str, str], None] = OrderedDict()
        self._lifecycle_lock = RLock()
        self._clean_session = False
        self._keepalive = 60
        self._push_cleanup_required = False
        self._connected = False
        self._last_connected_at: float | None = None
        self._last_disconnected_at: float | None = None
        self._last_message_at: float | None = None
        self._disconnected_since: float | None = None

        self._mqtt_data: MqttData = {
            "mqtt_clientid": None,
            "ticket": None,
            "push_url": token["service_urls"]["pushAddr"],
        }

        self.mqtt_client: mqtt.Client | None = None
        # Keep last payload per device, bounded by ``max_messages``
        self.messages_by_device: OrderedDict[str, dict[str, Any]] = OrderedDict()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self, *, clean_session: bool = False, keepalive: int = 60) -> None:
        """Connect to the Ezviz MQTT broker and start receiving push messages.

        This method performs the following steps:
            1. Registers the client with Ezviz push service.
            2. Starts push notifications for this client.
            3. Configures and connects the underlying MQTT client.
            4. Starts the MQTT network loop in a background thread.

        Keyword Args:
          clean_session (bool, optional): Whether to start a clean MQTT session. Defaults to False.
          keepalive (int, optional): Keep-alive interval in seconds for the MQTT connection. Defaults to 60.

        Raises:
          PyEzvizError: If required Ezviz credentials are missing or registration/start fails.
          InvalidURL: If a push API endpoint is invalid or unreachable.
          HTTPError: If a push API request returns a non-success status.
        """
        if keepalive < 1:
            raise ValueError("keepalive must be greater than zero")
        with self._lifecycle_lock:
            if self.mqtt_client is not None or self._push_cleanup_required:
                raise PyEzvizError("MQTT client is already started; call restart()")
            self._clean_session = clean_session
            self._keepalive = keepalive
            try:
                self._register_ezviz_push()
                self._start_ezviz_push()
                self._configure_mqtt(clean_session=clean_session)
                mqtt_client = self.mqtt_client
                if mqtt_client is None:  # pragma: no cover - defensive invariant
                    raise PyEzvizError("MQTT client was not configured")
                self._connected = False
                self._disconnected_since = time.monotonic()
                mqtt_client.connect(
                    self._mqtt_data["push_url"],
                    self._transport.port,
                    keepalive,
                )
                mqtt_client.loop_start()
            except Exception:
                self._disconnect_local()
                if self._push_cleanup_required:
                    try:
                        self._stop_ezviz_push()
                    except PyEzvizError as err:
                        _LOGGER.warning(
                            "Could not roll back EZVIZ push registration: %s",
                            err,
                        )
                    else:
                        self._push_cleanup_required = False
                raise

    def stop(self) -> None:
        """Stop the MQTT client and push notifications.

        This method stops the MQTT network loop, disconnects from the broker,
        and signals the Ezviz API to stop push notifications.

        This method is idempotent and can be called multiple times safely.

        Raises:
          PyEzvizError: If stopping the push service fails.
        """
        with self._lifecycle_lock:
            local_cleanup_complete = self._disconnect_local()
            if self._push_cleanup_required:
                self._stop_ezviz_push()
                self._push_cleanup_required = False
            if not local_cleanup_complete:
                raise PyEzvizError(
                    "MQTT local cleanup is incomplete; call stop() again"
                )

    def restart(self) -> None:
        """Perform a full push re-registration and MQTT reconnect.

        Paho handles ordinary transport reconnects itself. A long-running service
        can call this method after :attr:`disconnected_seconds` exceeds its health
        threshold to rebuild stale EZVIZ registration state.
        """

        with self._lifecycle_lock:
            if not self._disconnect_local():
                raise PyEzvizError(
                    "MQTT local cleanup is incomplete; retry restart()"
                )
            if self._push_cleanup_required:
                self._stop_ezviz_push()
                self._push_cleanup_required = False
            self.connect(clean_session=self._clean_session, keepalive=self._keepalive)

    @property
    def connected(self) -> bool:
        """Return whether the broker has acknowledged the current connection."""

        return self._connected

    @property
    def last_connected_at(self) -> float | None:
        """Return Unix time of the latest successful MQTT connection."""

        return self._last_connected_at

    @property
    def last_disconnected_at(self) -> float | None:
        """Return Unix time of the latest MQTT disconnection."""

        return self._last_disconnected_at

    @property
    def last_message_at(self) -> float | None:
        """Return Unix time of the latest valid MQTT JSON object."""

        return self._last_message_at

    @property
    def disconnected_seconds(self) -> float | None:
        """Return current disconnected duration using a monotonic clock."""

        if self._connected or self._disconnected_since is None:
            return None
        return max(0.0, time.monotonic() - self._disconnected_since)

    def _disconnect_local(self) -> bool:
        """Stop the local Paho loop and retain its handle when cleanup fails."""

        mqtt_client = self.mqtt_client
        if mqtt_client is None:
            self._connected = False
            self._last_disconnected_at = time.time()
            self._disconnected_since = time.monotonic()
            return True

        cleanup_complete = True
        disconnect_complete = True
        try:
            mqtt_client.loop_stop()
        except (OSError, ValueError, RuntimeError) as err:
            cleanup_complete = False
            _LOGGER.warning("MQTT loop stop failed and will be retried: %s", err)
        try:
            mqtt_client.disconnect()
        except (OSError, ValueError, RuntimeError) as err:
            cleanup_complete = False
            disconnect_complete = False
            _LOGGER.warning("MQTT disconnect failed and will be retried: %s", err)

        if disconnect_complete:
            self._connected = False
            self._last_disconnected_at = time.time()
            self._disconnected_since = time.monotonic()
        if cleanup_complete:
            self.mqtt_client = None
        else:
            self.mqtt_client = mqtt_client
        return cleanup_complete

    # ------------------------------------------------------------------
    # MQTT callbacks
    # ------------------------------------------------------------------

    def _on_subscribe(
        self, client: mqtt.Client, userdata: Any, mid: int, granted_qos: tuple[int, ...]
    ) -> None:
        """Handle subscription acknowledgement from the broker."""
        _LOGGER.debug(
            "MQTT subscribed: topic=%s mid=%s qos=%s", self._topic, mid, granted_qos
        )

    def _on_connect(
        self, client: mqtt.Client, userdata: Any, flags: dict, rc: int
    ) -> None:
        """Handle successful or failed MQTT connection attempts.

        Subscribes to the topic if this is a new session and logs connection status.

        Args:
            client (mqtt.Client): The MQTT client instance.
            userdata (Any): The user data passed to the client (not used).
            flags (dict): MQTT flags dictionary, includes 'session present'.
            rc (int): MQTT connection result code. 0 indicates success.
        """
        session_present = (
            flags.get("session present") if isinstance(flags, dict) else None
        )
        _LOGGER.debug("MQTT connected: rc=%s session_present=%s", rc, session_present)
        if rc == 0:
            self._connected = True
            self._last_connected_at = time.time()
            self._disconnected_since = None
            if not session_present:
                client.subscribe(self._topic, qos=2)
            return

        self._connected = False
        self._last_disconnected_at = time.time()
        self._disconnected_since = time.monotonic()
        # Let paho handle reconnects (reconnect_delay_set configured)
        _LOGGER.error(
            "MQTT connect failed: serial=%s code=%s msg=%s",
            "unknown",
            rc,
            "connect_failed",
        )

    def _on_disconnect(self, client: mqtt.Client, userdata: Any, rc: int) -> None:
        """Called when the MQTT client disconnects from the broker.

        Logs the disconnection. Automatic reconnects are handled by paho-mqtt.

        Args:
            client (mqtt.Client): The MQTT client instance.
            userdata (Any): The user data passed to the client (not used).
            rc (int): Disconnect result code. 0 indicates a clean disconnect.
        """
        self._connected = False
        self._last_disconnected_at = time.time()
        self._disconnected_since = time.monotonic()
        _LOGGER.debug(
            "MQTT disconnected: serial=%s code=%s msg=%s",
            "unknown",
            rc,
            "disconnected",
        )

    def _on_message(
        self, client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage
    ) -> None:
        """Handle incoming MQTT messages.

        Decodes the payload, updates `messages_by_device` with the latest message,
        and calls the optional user callback.

        Args:
            client (mqtt.Client): The MQTT client instance.
            userdata (Any): The user data passed to the client (not used).
            msg (mqtt.MQTTMessage): The MQTT message object containing payload and topic.
        """
        try:
            decoded = self.decode_mqtt_message(msg.payload)
        except PyEzvizError as err:
            _LOGGER.warning("MQTT decode error: msg=%s", str(err))
            return
        self._last_message_at = time.time()
        try:
            self._process_decoded_message(decoded)
        except Exception:
            # Broker payloads are untrusted. Never let an unexpected field shape
            # terminate Paho's network thread.
            _LOGGER.exception("MQTT message processing failed")

    def _process_decoded_message(self, decoded: dict[str, Any]) -> None:
        """Filter, cache, and deliver one validated JSON object."""

        ext: dict[str, Any] = (
            decoded.get("ext", {}) if isinstance(decoded.get("ext"), dict) else {}
        )
        device_serial = ext.get("device_serial")
        alert_code = ext.get("alert_type_code")
        msg_id = ext.get("msgId")

        allowed_device_serials = self._message_policy.allowed_device_serials
        if (
            allowed_device_serials is not None
            and str(device_serial) not in allowed_device_serials
        ):
            _LOGGER.debug("MQTT message ignored for device serial=%s", device_serial)
            return
        allowed_alert_types = self._message_policy.allowed_alert_types
        if allowed_alert_types is not None and (
                not isinstance(alert_code, int)
                or isinstance(alert_code, bool)
                or alert_code not in allowed_alert_types
        ):
            _LOGGER.debug(
                "MQTT message ignored for alert code=%s serial=%s",
                alert_code,
                device_serial,
            )
            return
        if self._is_duplicate_message(ext):
            _LOGGER.debug(
                "Duplicate MQTT message ignored: serial=%s msg_id=%s sequence=%s",
                device_serial,
                msg_id,
                ext.get("sequence_number"),
            )
            return

        if device_serial:
            self._cache_message(str(device_serial), decoded)
            _LOGGER.debug(
                "MQTT msg: serial=%s alert_code=%s msg_id=%s",
                device_serial,
                alert_code,
                msg_id,
            )
        else:
            _LOGGER.debug(
                "MQTT message missing serial: alert_code=%s msg_id=%s",
                alert_code,
                msg_id,
            )

        if self._on_message_callback:
            try:
                self._on_message_callback(decoded)
            except Exception:
                _LOGGER.exception("The on_message_callback raised")

    def _is_duplicate_message(self, ext: dict[str, Any]) -> bool:
        """Record a message identity and return whether it was seen before."""

        if not self._message_policy.deduplicate_messages:
            return False
        msg_id = ext.get("msgId")
        sequence_number = ext.get("sequence_number")
        if (
            not isinstance(msg_id, str | int)
            or isinstance(msg_id, bool)
            or msg_id == ""
        ):
            return False
        key = (
            str(ext.get("device_serial") or ""),
            str(msg_id or ""),
            str(sequence_number or ""),
        )
        if key in self._seen_message_ids:
            self._seen_message_ids.move_to_end(key)
            return True
        self._seen_message_ids[key] = None
        while (
            len(self._seen_message_ids)
            > self._message_policy.deduplication_cache_size
        ):
            self._seen_message_ids.popitem(last=False)
        return False

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _register_ezviz_push(self) -> None:
        """Register the client with the Ezviz push service.

        Sends the necessary information to Ezviz to obtain a unique MQTT client ID.

        Raises:
            PyEzvizError: If the registration fails or the API returns a non-200 status.
            InvalidURL: If the push service URL is invalid or unreachable.
            HTTPError: If the HTTP request fails for other reasons.
        """
        auth_seq = (
            "Basic "
            + base64.b64encode(f"{MQTT_APP_KEY}:{APP_SECRET}".encode("ascii")).decode()
        )

        payload = {
            "appKey": MQTT_APP_KEY,
            "clientType": "5",
            "mac": FEATURE_CODE,
            "token": "123456",
            "version": "v1.3.0",
        }

        try:
            req = self._session.post(
                f"https://{self._mqtt_data['push_url']}{API_ENDPOINT_REGISTER_MQTT}",
                allow_redirects=False,
                headers={"Authorization": auth_seq},
                data=payload,
                timeout=self._timeout,
            )
            req.raise_for_status()
        except requests.ConnectionError as err:
            raise InvalidURL("Invalid URL or proxy error") from err
        except requests.HTTPError as err:  # network OK, HTTP error status
            raise HTTPError from err

        try:
            json_output = req.json()
        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: "
                + str(err)
                + "Response was: "
                + str(req.text)
            ) from err

        if json_output.get("status") != 200:
            raise PyEzvizError(
                f"Could not register to EZVIZ mqtt server: Got {json_output})"
            )

        # Persist client id from payload
        self._mqtt_data["mqtt_clientid"] = json_output["data"]["clientId"]

    def _start_ezviz_push(self) -> None:
        """Start push notifications for this client with the Ezviz API.

        Sends the client ID, session ID, and username to Ezviz so that the server
        will start pushing messages to this client.

        Raises:
            PyEzvizError: If the API fails to start push notifications or returns a non-200 status.
            InvalidURL: If the push service URL is invalid or unreachable.
            HTTPError: If the HTTP request fails for other reasons.
        """
        payload = {
            "appKey": MQTT_APP_KEY,
            "clientId": self._mqtt_data["mqtt_clientid"],
            "clientType": 5,
            "sessionId": self._token["session_id"],
            "username": self._token["username"],
            "token": "123456",
        }

        # Once the request is attempted, the server may have created registration
        # state even if the response is lost or cannot be decoded.
        self._push_cleanup_required = True
        try:
            req = self._session.post(
                f"https://{self._mqtt_data['push_url']}{API_ENDPOINT_START_MQTT}",
                allow_redirects=False,
                data=payload,
                timeout=self._timeout,
            )
            req.raise_for_status()
        except requests.ConnectionError as err:
            raise InvalidURL("Invalid URL or proxy error") from err
        except requests.HTTPError as err:
            raise HTTPError from err

        try:
            json_output = req.json()
        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: "
                + str(err)
                + "Response was: "
                + str(req.text)
            ) from err

        if json_output.get("status") != 200:
            raise PyEzvizError(
                f"Could not signal EZVIZ mqtt server to start pushing messages: Got {json_output})"
            )

        self._mqtt_data["ticket"] = json_output["ticket"]
        _LOGGER.debug(
            "MQTT ticket acquired: client_id=%s", self._mqtt_data["mqtt_clientid"]
        )

    def _stop_ezviz_push(self) -> None:
        """Stop push notifications for this client via the Ezviz API.

        Sends the client ID and session information to stop further messages.

        Raises:
            PyEzvizError: If the API fails to stop push notifications or returns a non-200 status.
            InvalidURL: If the push service URL is invalid or unreachable.
            HTTPError: If the HTTP request fails for other reasons.
        """
        payload = {
            "appKey": MQTT_APP_KEY,
            "clientId": self._mqtt_data["mqtt_clientid"],
            "clientType": 5,
            "sessionId": self._token["session_id"],
            "username": self._token["username"],
        }

        try:
            req = self._session.post(
                f"https://{self._mqtt_data['push_url']}{API_ENDPOINT_STOP_MQTT}",
                data=payload,
                timeout=self._timeout,
            )
            req.raise_for_status()
        except requests.ConnectionError as err:
            raise InvalidURL("Invalid URL or proxy error") from err
        except requests.HTTPError as err:
            raise HTTPError from err

        try:
            json_output = req.json()
        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: "
                + str(err)
                + "Response was: "
                + str(req.text)
            ) from err

        if json_output.get("status") != 200:
            raise PyEzvizError(
                f"Could not signal EZVIZ mqtt server to stop pushing messages: Got {json_output})"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _configure_mqtt(self, *, clean_session: bool) -> None:
        """Internal helper to configure and connect the paho-mqtt client.

        This method sets up the MQTT client with:
            - Callbacks for connect, disconnect, subscribe, and message
            - Username and password authentication
            - Reconnect delay settings
            - Broker connection on the configured topic

        Args:
            clean_session (bool): Whether to start a clean MQTT session.

        Notes:
            This method is called automatically by `connect()`.

        """
        broker = self._mqtt_data["push_url"]

        client_kwargs: dict[str, Any] = {
            "client_id": self._mqtt_data["mqtt_clientid"],
            "clean_session": clean_session,
            "protocol": mqtt.MQTTv311,
            "transport": "tcp",
        }
        callback_api_version = getattr(mqtt, "CallbackAPIVersion", None)
        if callback_api_version is not None:
            client_kwargs["callback_api_version"] = callback_api_version.VERSION1

        mqtt_client = mqtt.Client(**client_kwargs)
        self.mqtt_client = mqtt_client

        # Bind callbacks
        mqtt_client.on_connect = self._on_connect
        mqtt_client.on_disconnect = self._on_disconnect
        mqtt_client.on_subscribe = self._on_subscribe
        mqtt_client.on_message = self._on_message

        # Auth (do not log these!)
        mqtt_client.username_pw_set(MQTT_APP_KEY, APP_SECRET)
        if self._transport.use_tls:
            context = self._transport.tls_context or ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH
            )
            context.minimum_version = max(
                context.minimum_version,
                ssl.TLSVersion.TLSv1_2,
            )
            mqtt_client.tls_set_context(context)

        # Backoff for reconnects handled by paho
        mqtt_client.reconnect_delay_set(min_delay=5, max_delay=120)

        _LOGGER.debug("Configured MQTT client for broker %s", broker)

    def _cache_message(self, device_serial: str, payload: dict[str, Any]) -> None:
        """Cache latest message per device with an LRU-like policy.

        Parameters:
            device_serial (str): Device serial extracted from the message ``ext``.
            payload (dict[str, Any]): Decoded message dictionary to store.
        """
        # Move existing to the end or insert new
        if device_serial in self.messages_by_device:
            del self.messages_by_device[device_serial]
        self.messages_by_device[device_serial] = payload
        # Evict oldest if above limit
        while len(self.messages_by_device) > self._max_messages:
            self.messages_by_device.popitem(last=False)

    # ------------------------------------------------------------------
    # Public decoding API
    # ------------------------------------------------------------------

    def decode_mqtt_message(self, payload_bytes: bytes) -> dict[str, Any]:
        """Decode raw MQTT message payload into a structured dictionary.

        The returned dictionary will contain all top-level fields from the message,
        and the 'ext' field is parsed into named subfields with numeric fields converted to int.

        Parameters:
            payload_bytes (bytes): Raw payload received from MQTT broker.

        Returns:
            dict: Decoded message with ``ext`` mapped to named fields; numeric fields
            converted to ``int`` where appropriate.

        Raises:
            PyEzvizError: If the payload is oversized, not UTF-8, not valid JSON,
                or does not decode to a JSON object.
        """
        if not isinstance(payload_bytes, bytes | bytearray):
            raise PyEzvizError("MQTT payload must be bytes")
        if len(payload_bytes) > self._message_policy.max_payload_size:
            raise PyEzvizError(
                "MQTT payload exceeds maximum size "
                f"({len(payload_bytes)} > "
                f"{self._message_policy.max_payload_size} bytes)"
            )
        raw_payload = bytes(payload_bytes)
        _validate_json_nesting(
            raw_payload,
            maximum=self._message_policy.max_json_nesting,
        )
        try:
            payload_str = raw_payload.decode("utf-8")
            parsed = json.loads(payload_str)
        except (ValueError, RecursionError) as err:
            raise PyEzvizError(f"Unable to decode MQTT message: {err}") from err

        if not isinstance(parsed, dict):
            raise PyEzvizError("Unable to decode MQTT message: JSON root must be an object")
        data: dict[str, Any] = parsed
        if "ext" in data and isinstance(data["ext"], str):
            ext_parts = data["ext"].split(",", len(EXT_FIELD_NAMES))
            ext_dict: dict[str, Any] = {}
            for i, name in enumerate(EXT_FIELD_NAMES):
                value: Any = ext_parts[i] if i < len(ext_parts) else None
                if value is not None and name in EXT_INT_FIELDS:
                    with suppress(ValueError):
                        value = int(value)
                ext_dict[name] = value
            data["ext"] = ext_dict

        return data
