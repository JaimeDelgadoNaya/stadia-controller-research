"""Fase 97: laboratorio puramente offline del protocolo USB Switch Pro NS1.

Emula SOLO la forma de respuestas a comandos conocidos y una pequeña memoria SPI
con calibraciones SINTÉTICAS; no implementa descriptor USB físico, ejecución de
firmware, Wi-Fi, BLE, entrada SDP ni acceso a Switch 2.
"""
from __future__ import annotations

from dataclasses import dataclass, field

MAX_SPI_READ = 0x1D
SYNTHETIC_MAC = bytes.fromhex("020000000097")  # local, inventada
# Accesos documentados públicamente; no memoria personal de un mando real.
ALLOWLIST_SPI = frozenset({
    (0x6000, 0x10), (0x6020, 0x18), (0x603D, 0x19),
    (0x6050, 0x18), (0x6080, 0x18), (0x6098, 0x12),
    (0x8010, 0x18), (0x8028, 0x18),
})


class UnsupportedProtocol(ValueError):
    """Comando no cubierto, forma inválida o capacidad no disponible."""


def pack12(x: int, y: int) -> bytes:
    if not all(type(n) is int and 0 <= n <= 4095 for n in (x, y)):
        raise ValueError("Expected 12-bit stick axes")
    return bytes((x & 0xFF, (x >> 8) | ((y & 0xF) << 4), y >> 4))


def unpack12(data: bytes) -> tuple[int, int]:
    if type(data) is not bytes or len(data) != 3:
        raise ValueError("Expected three bytes")
    return data[0] | ((data[1] & 0x0F) << 8), (data[1] >> 4) | (data[2] << 4)


@dataclass(frozen=True)
class SyntheticFactorySPI:
    """Regiones FIJAS creadas localmente; no contienen una calibración Nintendo."""
    data: bytes = field(init=False, repr=False)

    def __post_init__(self):
        ram = bytearray(b"\xFF" * 0x10000)
        # Dos sticks: 9 bytes = tres pares de ejes de 12 bits cada uno.
        # Son VALORES INVENTADOS para demostrar empaquetado; no factory dump.
        stick = pack12(0x700, 0x700) + pack12(0x800, 0x800) + pack12(0x700, 0x700)
        ram[0x603D:0x604F] = stick + stick
        # 0x604F es separador FF, después seis bytes de "color" sintético.
        ram[0x6050:0x6056] = bytes(6)
        ram[0x6020:0x6038] = bytes(0x18)  # no implica sensor IMU real
        ram[0x6080:0x6098] = bytes(0x18)  # marcadores sintéticos
        ram[0x6098:0x60AA] = bytes(0x12)
        # 0x8010 y 0x8028 quedan FF: no se usará identidad/calibración privada.
        object.__setattr__(self, "data", bytes(ram))

    def read(self, address: int, length: int) -> bytes:
        if type(address) is not int or type(length) is not int:
            raise UnsupportedProtocol("SPI address and size must be integers")
        if not 1 <= length <= MAX_SPI_READ:
            raise UnsupportedProtocol("Invalid SPI read length")
        if (address, length) not in ALLOWLIST_SPI:
            raise UnsupportedProtocol("SPI read not on public test allowlist")
        return self.data[address:address + length]


def make_host_subcommand(subcommand: int, args: bytes = b"", packet_number: int = 0) -> bytes:
    """Reporte de SALIDA 0x01 (solo bytes, nunca enviado al hardware)."""
    if type(subcommand) is not int or not 0 <= subcommand <= 255:
        raise ValueError("Invalid subcommand")
    if type(args) is not bytes or len(args) > 42:
        raise ValueError("Invalid argument bytes")
    if type(packet_number) is not int or not 0 <= packet_number <= 255:
        raise ValueError("Invalid packet number")
    return bytes((0x01, packet_number)) + bytes(8) + bytes((subcommand,)) + args


@dataclass
class VirtualNS1Pro97:
    """Modelo de host/dispositivo, incompleto por diseño; falla cerrado."""
    phase: str = "fresh"
    report_mode: int | None = None
    tick: int = 0
    leds: int = 0
    vibration_enabled: bool = False
    imu_enabled: bool = False
    flash: SyntheticFactorySPI = field(default_factory=SyntheticFactorySPI)

    def _reply(self, subcommand: int, ack: int = 0x80, payload: bytes = b"") -> bytes:
        if len(payload) > 49:
            raise UnsupportedProtocol("Reply does not fit a 64-byte report")
        r = bytearray(64)
        r[0] = 0x21
        r[1] = self.tick & 255
        r[2] = 0x80  # sólo una bandera sintética de conexión
        r[6:12] = pack12(0x800, 0x800) * 2
        r[12] = 0x08
        r[13] = ack
        r[14] = subcommand
        r[15:15 + len(payload)] = payload
        self.tick = (self.tick + 1) & 255
        return bytes(r)

    def process(self, output: bytes) -> bytes | None:
        if type(output) is not bytes or len(output) < 2:
            raise UnsupportedProtocol("Truncated USB output report")
        if output[0] == 0x80:
            sub = output[1]
            if len(output) != 2:
                raise UnsupportedProtocol("Synthetic init accepts exact two bytes")
            if sub == 1 and self.phase == "fresh":
                self.phase = "identified"
                return bytes((0x81, 1, 0, 3)) + SYNTHETIC_MAC
            if sub == 2 and self.phase in ("identified", "baud"):
                self.phase = "handshake"
                return b"\x81\x02"
            if sub == 3 and self.phase == "handshake":
                self.phase = "baud"
                return b"\x81\x03"
            if sub == 4 and self.phase in ("handshake", "baud"):
                self.phase = "usb_ready"
                return None
            raise UnsupportedProtocol("Unmodeled USB init order or subcommand")
        if self.phase != "usb_ready":
            raise UnsupportedProtocol("USB initialization not finished")
        if output[0] == 0x10:
            return None  # output rumble ignored; motor hardware unavailable
        if output[0] != 0x01 or len(output) < 11:
            raise UnsupportedProtocol("Expected full 0x01 subcommand header")
        sub, args = output[10], output[11:]
        if sub == 0x10:
            if len(args) < 5:
                raise UnsupportedProtocol("Truncated SPI read request")
            address = int.from_bytes(args[:4], "little")
            amount = args[4]
            data = self.flash.read(address, amount)
            return self._reply(0x10, 0x90, args[:5] + data)
        if sub == 0x02:
            # Identificador y firmware INVENTADOS, no respuesta real del fabricante.
            return self._reply(0x02, 0x82, bytes((3, 0, 3, 2)) + SYNTHETIC_MAC + b"\x00\x00")
        if sub == 0x03:
            if not args or args[0] != 0x30:
                raise UnsupportedProtocol("Only full 0x30 report mode is modeled")
            self.report_mode = 0x30
            return self._reply(0x03)
        if sub == 0x08:
            return self._reply(0x08)  # No persistencia del modo envío
        if sub == 0x04:
            return self._reply(0x04, 0x83, bytes(8))  # tiempo ficticio
        if sub == 0x30:
            if not args:
                raise UnsupportedProtocol("Missing player-light byte")
            self.leds = args[0]
            return self._reply(0x30)
        if sub == 0x40:
            if not args:
                raise UnsupportedProtocol("Missing IMU flag")
            if args[0]:
                raise UnsupportedProtocol("No real motion/IMU stream modeled")
            self.imu_enabled = False
            return self._reply(0x40)
        if sub == 0x48:
            if not args:
                raise UnsupportedProtocol("Missing vibration flag")
            self.vibration_enabled = bool(args[0])
            return self._reply(0x48)
        raise UnsupportedProtocol(f"Subcommand 0x{sub:02x} not modeled")

    def can_stream(self) -> bool:
        return self.phase == "usb_ready" and self.report_mode == 0x30


def run_offline_trace() -> dict[str, object]:
    """Host script del SUBCONJUNTO público, no inicialización probada de Switch2."""
    d = VirtualNS1Pro97()
    control = (b"\x80\x01", b"\x80\x02", b"\x80\x03", b"\x80\x04")
    rows: list[dict[str, object]] = []
    for cmd in control:
        response = d.process(cmd)
        rows.append({"host": cmd.hex(), "reply_type": response[0] if response else None})
    for address, length in ((0x6000, 0x10), (0x603D, 0x19),
                            (0x6080, 0x18), (0x8010, 0x18)):
        request = make_host_subcommand(0x10, address.to_bytes(4, "little") + bytes((length,)))
        response = d.process(request)
        assert response is not None and response[13:15] == b"\x90\x10"
        rows.append({"host": f"SPI 0x{address:04x}/{length}",
                     "reply_type": response[0], "ack": response[13],
                     "payload_len": len(response[20:20 + length])})
    for cmd, args in ((0x02, b""), (0x03, b"\x30"),
                      (0x40, b"\x00"), (0x48, b"\x01"), (0x30, b"\x01")):
        response = d.process(make_host_subcommand(cmd, args))
        rows.append({"host": f"subcmd 0x{cmd:02x}", "reply_type": response[0],
                     "ack": response[13]})
    blocked: list[str] = []
    for cmd, args in ((0x21, b""), (0x40, b"\x01"),
                      (0x10, (0x7000).to_bytes(4, "little") + b"\x18")):
        try:
            d.process(make_host_subcommand(cmd, args))
        except UnsupportedProtocol as exc:
            blocked.append(str(exc))
        else:
            raise AssertionError("Missing capability was accepted")
    return {"steps": rows, "supported_host_subset": d.can_stream(),
            "blocked_scenarios": blocked,
            "full_switch2_console_handshake_proven": False,
            "original_pro_usb_descriptor_emitted": False,
            "stadia_retail_custom_firmware_boot_proven": False,
            "actual_devices_contacted": False,
            "calibration_data_origin": "synthetic_only"}


if __name__ == "__main__":
    import json
    print(json.dumps(run_offline_trace(), indent=2))
