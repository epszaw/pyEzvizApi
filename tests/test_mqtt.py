from __future__ import annotations

import json
import ssl
from typing import Any

import pytest
import requests

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.mqtt import MQTTClient, MqttMessagePolicy, MqttTransportConfig

TOKEN = {
    "username": "ezviz-user",
    "session_id": "session-id",
    "service_urls": {"pushAddr": "push.example.test"},
}


class OfflineMQTTClient(MQTTClient):
    """MQTT client that never calls the EZVIZ stop endpoint in tests."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.stop_called = False

    def stop(self) -> None:
        self.stop_called = True


class DummyMessage:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload


def _client(**kwargs: Any) -> OfflineMQTTClient:
    return OfflineMQTTClient(TOKEN, requests.Session(), **kwargs)


def _mark_push_registration(client: MQTTClient) -> None:
    client._push_cleanup_required = True


def test_decode_mqtt_message_expands_ext_fields_and_coerces_ints() -> None:
    client = _client()
    raw = {
        "alert": "Motion detected",
        "ext": "1,2026-04-27 07:30:00,CAM123,2,2401,default.jpg,alt1.jpg,alt2.jpg,3,1,file-1,0,checksum,1,metadata,msg-1,image.jpg,Front Door,reserved,42",
    }

    decoded = client.decode_mqtt_message(json.dumps(raw).encode())

    assert decoded["alert"] == "Motion detected"
    assert decoded["ext"] == {
        "channel_type": 1,
        "time": "2026-04-27 07:30:00",
        "device_serial": "CAM123",
        "channel_no": 2,
        "alert_type_code": 2401,
        "default_pic_url": "default.jpg",
        "media_url_alt1": "alt1.jpg",
        "media_url_alt2": "alt2.jpg",
        "resource_type": 3,
        "status_flag": 1,
        "file_id": "file-1",
        "is_encrypted": 0,
        "picChecksum": "checksum",
        "is_dev_video": 1,
        "metadata": "metadata",
        "msgId": "msg-1",
        "image": "image.jpg",
        "device_name": "Front Door",
        "reserved": "reserved",
        "sequence_number": 42,
    }


def test_decode_mqtt_message_fills_missing_ext_fields_with_none() -> None:
    client = _client()
    decoded = client.decode_mqtt_message(b'{"ext": "1,time,CAM123"}')

    assert decoded["ext"]["channel_type"] == 1
    assert decoded["ext"]["time"] == "time"
    assert decoded["ext"]["device_serial"] == "CAM123"
    assert decoded["ext"]["msgId"] is None
    assert decoded["ext"]["sequence_number"] is None


def test_decode_mqtt_message_raises_without_stopping_on_malformed_json() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Unable to decode MQTT message"):
        client.decode_mqtt_message(b"not-json")

    assert client.stop_called is False


@pytest.mark.parametrize("payload", [b"\xff", b"[]", b'"scalar"'])
def test_decode_mqtt_message_rejects_non_object_payloads(payload: bytes) -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Unable to decode MQTT message"):
        client.decode_mqtt_message(payload)


def test_decode_mqtt_message_rejects_oversized_payload() -> None:
    client = _client(message_policy=MqttMessagePolicy(max_payload_size=8))

    with pytest.raises(PyEzvizError, match="exceeds maximum size"):
        client.decode_mqtt_message(b'{"value": 1}')


def test_decode_mqtt_message_rejects_excessive_nesting() -> None:
    client = _client()
    payload = b'{"nested":' + (b"[" * 2000) + b"0" + (b"]" * 2000) + b"}"

    with pytest.raises(PyEzvizError, match="Unable to decode MQTT message"):
        client.decode_mqtt_message(payload)


def test_decode_mqtt_message_ignores_brackets_inside_strings() -> None:
    client = _client(message_policy=MqttMessagePolicy(max_json_nesting=1))

    decoded = client.decode_mqtt_message(
        json.dumps({"value": '[[{{\\"quoted"}}]]'}).encode()
    )

    assert decoded["value"] == '[[{{\\"quoted"}}]]'


def test_decode_mqtt_message_wraps_json_integer_limit_errors() -> None:
    client = _client()
    payload = b'{"value":' + (b"9" * 5000) + b"}"

    with pytest.raises(PyEzvizError, match="Unable to decode MQTT message"):
        client.decode_mqtt_message(payload)


def test_on_message_caches_by_device_and_invokes_callback() -> None:
    seen: list[dict[str, Any]] = []
    client = _client(on_message_callback=seen.append)
    message = DummyMessage(
        json.dumps({"alert": "Person", "ext": "1,time,CAM123,1,2403"}).encode()
    )

    client._on_message(None, None, message)  # type: ignore[arg-type]

    assert list(client.messages_by_device) == ["CAM123"]
    assert client.messages_by_device["CAM123"]["alert"] == "Person"
    assert seen == [client.messages_by_device["CAM123"]]


def test_on_message_drops_malformed_payload_without_stopping() -> None:
    seen: list[dict[str, Any]] = []
    client = _client(on_message_callback=seen.append)

    client._on_message(None, None, DummyMessage(b"not-json"))  # type: ignore[arg-type]

    assert seen == []
    assert client.stop_called is False


def test_on_message_filters_device_and_alert_type() -> None:
    seen: list[dict[str, Any]] = []
    client = _client(
        on_message_callback=seen.append,
        message_policy=MqttMessagePolicy(
            allowed_device_serials={"CAM123"},
            allowed_alert_types={2402},
        ),
    )

    client._on_message(  # type: ignore[arg-type]
        None,
        None,
        DummyMessage(json.dumps({"ext": "1,time,OTHER,1,2402"}).encode()),
    )
    client._on_message(  # type: ignore[arg-type]
        None,
        None,
        DummyMessage(json.dumps({"ext": "1,time,CAM123,1,2403"}).encode()),
    )
    client._on_message(  # type: ignore[arg-type]
        None,
        None,
        DummyMessage(json.dumps({"ext": "1,time,CAM123,1,2402"}).encode()),
    )

    assert len(seen) == 1
    assert seen[0]["ext"]["device_serial"] == "CAM123"
    assert seen[0]["ext"]["alert_type_code"] == 2402


def test_on_message_drops_unhashable_structured_alert_type() -> None:
    seen: list[dict[str, Any]] = []
    client = _client(
        on_message_callback=seen.append,
        message_policy=MqttMessagePolicy(
            allowed_device_serials={"CAM123"},
            allowed_alert_types={2402},
        ),
    )
    payload = json.dumps(
        {
            "ext": {
                "device_serial": "CAM123",
                "alert_type_code": [],
            }
        }
    ).encode()

    client._on_message(None, None, DummyMessage(payload))  # type: ignore[arg-type]

    assert seen == []


def test_on_message_contains_unexpected_processing_error(monkeypatch) -> None:
    client = _client()
    monkeypatch.setattr(
        client,
        "_process_decoded_message",
        lambda _decoded: (_ for _ in ()).throw(TypeError("unexpected shape")),
    )

    client._on_message(None, None, DummyMessage(b"{}"))  # type: ignore[arg-type]

    assert client.last_message_at is not None


def test_on_message_deduplicates_by_message_identity() -> None:
    seen: list[dict[str, Any]] = []
    client = _client(
        on_message_callback=seen.append,
        message_policy=MqttMessagePolicy(deduplicate_messages=True),
    )
    payload = json.dumps(
        {
            "ext": (
                "1,time,CAM123,1,2402,pic.jpg,,,,,,,,,,msg-1,,,,42"
            )
        }
    ).encode()

    client._on_message(None, None, DummyMessage(payload))  # type: ignore[arg-type]
    client._on_message(None, None, DummyMessage(payload))  # type: ignore[arg-type]

    assert len(seen) == 1
    assert seen[0]["ext"]["msgId"] == "msg-1"
    assert seen[0]["ext"]["sequence_number"] == 42


def test_on_message_does_not_deduplicate_sequence_without_message_id() -> None:
    seen: list[dict[str, Any]] = []
    client = _client(
        on_message_callback=seen.append,
        message_policy=MqttMessagePolicy(deduplicate_messages=True),
    )
    ext = [""] * 20
    ext[2] = "CAM123"
    ext[4] = "2402"
    ext[19] = "42"
    payload = json.dumps({"ext": ",".join(ext)}).encode()

    client._on_message(None, None, DummyMessage(payload))  # type: ignore[arg-type]
    client._on_message(None, None, DummyMessage(payload))  # type: ignore[arg-type]

    assert len(seen) == 2


def test_connection_callbacks_expose_health_state() -> None:
    client = _client()

    class FakePahoClient:
        def __init__(self) -> None:
            self.subscriptions: list[tuple[str, int]] = []

        def subscribe(self, topic: str, qos: int) -> None:
            self.subscriptions.append((topic, qos))

    paho_client = FakePahoClient()
    client._on_connect(  # type: ignore[arg-type]
        paho_client,
        None,
        {"session present": False},
        0,
    )

    assert client.connected is True
    assert client.last_connected_at is not None
    assert client.disconnected_seconds is None
    assert paho_client.subscriptions == [(client._topic, 2)]

    client._on_disconnect(paho_client, None, 1)  # type: ignore[arg-type]

    assert client.connected is False
    assert client.last_disconnected_at is not None
    assert client.disconnected_seconds is not None


def test_configure_mqtt_enables_strict_tls(monkeypatch) -> None:
    calls: dict[str, Any] = {}

    class FakePahoClient:
        on_connect = None
        on_disconnect = None
        on_subscribe = None
        on_message = None

        def username_pw_set(self, username: str, password: str) -> None:
            calls["credentials"] = (username, password)

        def tls_set_context(self, context: Any) -> None:
            calls["tls_context"] = context

        def reconnect_delay_set(self, *, min_delay: int, max_delay: int) -> None:
            calls["reconnect_delay"] = (min_delay, max_delay)

    fake_paho_client = FakePahoClient()
    monkeypatch.setattr(
        "pyezvizapi.mqtt.mqtt.Client",
        lambda **_kwargs: fake_paho_client,
    )
    client = _client(transport=MqttTransportConfig(use_tls=True, port=8883))

    client._configure_mqtt(clean_session=False)

    assert calls["tls_context"].check_hostname is True
    assert calls["reconnect_delay"] == (5, 120)


def test_transport_rejects_insecure_tls_context() -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with pytest.raises(ValueError, match="certificate and hostname"):
        MqttTransportConfig(use_tls=True, tls_context=context)


def test_connect_uses_transport_port_and_rejects_double_start(monkeypatch) -> None:
    calls: dict[str, Any] = {}
    client = _client(transport=MqttTransportConfig(port=2883))

    class FakePahoClient:
        def connect(self, host: str, port: int, keepalive: int) -> None:
            calls["connect"] = (host, port, keepalive)

        def loop_start(self) -> None:
            calls["loop_started"] = True

        def loop_stop(self) -> None:
            calls["loop_stopped"] = True

        def disconnect(self) -> None:
            calls["disconnected"] = True

    def fake_start() -> None:
        _mark_push_registration(client)

    def fake_configure(*, clean_session: bool) -> None:
        calls["clean_session"] = clean_session
        client.mqtt_client = FakePahoClient()  # type: ignore[assignment]

    monkeypatch.setattr(client, "_register_ezviz_push", lambda: None)
    monkeypatch.setattr(client, "_start_ezviz_push", fake_start)
    monkeypatch.setattr(client, "_configure_mqtt", fake_configure)

    client.connect(clean_session=False, keepalive=30)

    assert calls["connect"] == ("push.example.test", 2883, 30)
    assert calls["loop_started"] is True
    assert client._push_cleanup_required is True
    with pytest.raises(PyEzvizError, match="already started"):
        client.connect()


def test_connect_rolls_back_push_registration_after_transport_failure(
    monkeypatch,
) -> None:
    calls: list[str] = []
    client = _client()

    class FailingPahoClient:
        def connect(self, _host: str, _port: int, _keepalive: int) -> None:
            raise OSError("broker unavailable")

        def loop_start(self) -> None:
            raise AssertionError("loop must not start after connect failure")

        def loop_stop(self) -> None:
            calls.append("loop_stop")

        def disconnect(self) -> None:
            calls.append("disconnect")

    def fake_start() -> None:
        _mark_push_registration(client)

    def fake_configure(*, clean_session: bool) -> None:
        client.mqtt_client = FailingPahoClient()  # type: ignore[assignment]

    monkeypatch.setattr(client, "_register_ezviz_push", lambda: None)
    monkeypatch.setattr(client, "_start_ezviz_push", fake_start)
    monkeypatch.setattr(client, "_configure_mqtt", fake_configure)
    monkeypatch.setattr(client, "_stop_ezviz_push", lambda: calls.append("push_stop"))

    with pytest.raises(OSError, match="broker unavailable"):
        client.connect()

    assert calls == ["loop_stop", "disconnect", "push_stop"]
    assert client.mqtt_client is None
    assert client._push_cleanup_required is False


def test_connect_retains_registration_when_rollback_fails(monkeypatch) -> None:
    client = _client()

    class FailingPahoClient:
        def connect(self, _host: str, _port: int, _keepalive: int) -> None:
            raise OSError("broker unavailable")

        def loop_stop(self) -> None:
            return None

        def disconnect(self) -> None:
            return None

    def fake_start() -> None:
        _mark_push_registration(client)

    def fake_configure(*, clean_session: bool) -> None:
        client.mqtt_client = FailingPahoClient()  # type: ignore[assignment]

    def fail_stop() -> None:
        raise PyEzvizError("push stop unavailable")

    monkeypatch.setattr(client, "_register_ezviz_push", lambda: None)
    monkeypatch.setattr(client, "_start_ezviz_push", fake_start)
    monkeypatch.setattr(client, "_configure_mqtt", fake_configure)
    monkeypatch.setattr(client, "_stop_ezviz_push", fail_stop)

    with pytest.raises(OSError, match="broker unavailable"):
        client.connect()

    assert client.mqtt_client is None
    assert client._push_cleanup_required is True


def test_connect_rolls_back_when_start_response_is_lost(monkeypatch) -> None:
    calls: list[str] = []
    client = _client()

    class FakeResponse:
        def __init__(self, *, malformed: bool) -> None:
            self.malformed = malformed
            self.text = "malformed" if malformed else '{"status": 200}'

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            if self.malformed:
                raise ValueError("response lost")
            return {"status": 200}

    class FakeSession:
        def post(self, url: str, **_kwargs: Any) -> FakeResponse:
            if url.endswith("/api/push/start"):
                calls.append("start")
                return FakeResponse(malformed=True)
            calls.append("stop")
            return FakeResponse(malformed=False)

    def fake_register() -> None:
        client._mqtt_data["mqtt_clientid"] = "client-id"

    client._session = FakeSession()  # type: ignore[assignment]
    monkeypatch.setattr(client, "_register_ezviz_push", fake_register)

    with pytest.raises(PyEzvizError, match="Impossible to decode response"):
        client.connect()

    assert calls == ["start", "stop"]
    assert client._push_cleanup_required is False


def test_restart_rebuilds_registration_with_previous_connection_settings(
    monkeypatch,
) -> None:
    calls: list[Any] = []
    client = _client()

    class FakePahoClient:
        def loop_stop(self) -> None:
            calls.append("loop_stop")

        def disconnect(self) -> None:
            calls.append("disconnect")

    client.mqtt_client = FakePahoClient()  # type: ignore[assignment]
    _mark_push_registration(client)
    client._clean_session = True
    client._keepalive = 45
    monkeypatch.setattr(client, "_stop_ezviz_push", lambda: calls.append("push_stop"))
    monkeypatch.setattr(
        client,
        "connect",
        lambda **kwargs: calls.append(("connect", kwargs)),
    )

    client.restart()

    assert calls == [
        "loop_stop",
        "disconnect",
        "push_stop",
        ("connect", {"clean_session": True, "keepalive": 45}),
    ]


def test_stop_is_idempotent(monkeypatch) -> None:
    calls: list[str] = []
    client = MQTTClient(TOKEN, requests.Session())

    class FakePahoClient:
        def loop_stop(self) -> None:
            calls.append("loop_stop")

        def disconnect(self) -> None:
            calls.append("disconnect")

    client.mqtt_client = FakePahoClient()  # type: ignore[assignment]
    _mark_push_registration(client)
    monkeypatch.setattr(client, "_stop_ezviz_push", lambda: calls.append("push_stop"))

    client.stop()
    client.stop()

    assert calls == ["loop_stop", "disconnect", "push_stop"]


def test_stop_retains_failed_remote_registration_for_retry(monkeypatch) -> None:
    calls: list[str] = []
    client = MQTTClient(TOKEN, requests.Session())
    _mark_push_registration(client)

    def fail_stop() -> None:
        calls.append("failed")
        raise PyEzvizError("temporary stop failure")

    monkeypatch.setattr(client, "_stop_ezviz_push", fail_stop)

    with pytest.raises(PyEzvizError, match="temporary stop failure"):
        client.stop()

    assert client._push_cleanup_required is True

    monkeypatch.setattr(client, "_stop_ezviz_push", lambda: calls.append("retried"))
    client.stop()

    assert calls == ["failed", "retried"]
    assert client._push_cleanup_required is False


def test_stop_attempts_all_local_cleanup_and_retains_failed_client() -> None:
    calls: list[str] = []
    client = MQTTClient(TOKEN, requests.Session())

    class RetryablePahoClient:
        fail_loop_stop = True

        def loop_stop(self) -> None:
            calls.append("loop_stop")
            if self.fail_loop_stop:
                self.fail_loop_stop = False
                raise RuntimeError("loop still stopping")

        def disconnect(self) -> None:
            calls.append("disconnect")

    paho_client = RetryablePahoClient()
    client.mqtt_client = paho_client  # type: ignore[assignment]

    with pytest.raises(PyEzvizError, match="local cleanup is incomplete"):
        client.stop()

    assert calls == ["loop_stop", "disconnect"]
    assert client.mqtt_client is paho_client

    client.stop()

    assert calls == ["loop_stop", "disconnect", "loop_stop", "disconnect"]
    assert client.mqtt_client is None


def test_restart_aborts_when_remote_registration_cannot_stop(monkeypatch) -> None:
    client = _client()
    _mark_push_registration(client)
    monkeypatch.setattr(
        client,
        "_stop_ezviz_push",
        lambda: (_ for _ in ()).throw(PyEzvizError("stop failed")),
    )
    monkeypatch.setattr(
        client,
        "connect",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("connect must not replace a failed registration")
        ),
    )

    with pytest.raises(PyEzvizError, match="stop failed"):
        client.restart()

    assert client._push_cleanup_required is True


def test_message_cache_evicts_oldest_device() -> None:
    client = _client(max_messages=2)

    client._cache_message("A", {"serial": "A"})
    client._cache_message("B", {"serial": "B"})
    client._cache_message("C", {"serial": "C"})

    assert list(client.messages_by_device) == ["B", "C"]

    client._cache_message("B", {"serial": "B", "updated": True})

    assert list(client.messages_by_device) == ["C", "B"]
    assert client.messages_by_device["B"] == {"serial": "B", "updated": True}
