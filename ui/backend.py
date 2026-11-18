"""
Backend of the live-demo UI. It contains NO Streamlit code, so it can be
tested with pytest (tests/test_ui_backend.py).

It only *drives* the existing simulation - nothing security-related is
re-implemented here:

* demo.harness       create_context(), attempt_update(), ScenarioResult
* demo.scenarios     SCENARIOS (1-10)
* attacks/*.py       the attack scenarios (via SCENARIOS)
* common.log         its add_file_sink() hook is used to capture log lines

What it adds for the UI:

* load_context()          reuse the on-disk device between page reloads
* prepare_for_scenario()  bring the device into the starting state a scenario expects
* run_scenario() / run_manual_update() / run_all()
                          run something, capture its log, record every update
                          attempt (UpdateResult + BootResult) and the served manifest
* update_steps()          map an UpdateResult onto the 8 steps of the secure procedure

User-visible strings are Turkish (the audience is Turkish students).
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from attacks import (
    downgrade,
    fake_server_wrong_key,
    interrupted_download,
    manifest_version_forgery,
    tamper_in_transit,
)
from common import log
from common.crypto_utils import load_public_key
from common.manifest import parse_manifest, verify_manifest
from common.paths import DEVICE_FLASH_DIR, KEYS_DIR, RELEASES_DIR, TRUSTED_KEY_PATH
from common.version import compare_versions
from demo.harness import (
    FACTORY_VERSION,
    ScenarioResult,
    SimContext,
    attempt_update,
    create_context,
    load_build_definitions,
)
from demo.scenarios import SCENARIOS, scenario_1_normal_update
from device.bootloader import BootResult
from device.device import Device
from device.flash import EMPTY, INVALID, PENDING_VERIFY, VALID, WRITING
from device.ota_client import ABORTED, INSTALLED, REJECTED, PowerLoss, UpdateResult

PREPARED_VERSION = "1.1.0"     # starting point of scenarios 2-9 (see attacks/_standalone.py)

# Pseudo result words (besides INSTALLED / REJECTED / ABORTED from ota_client)
ROLLBACK = "ROLLBACK"
POWER_LOSS = "GÜÇ KAYBI"

STATE_LABELS_TR = {
    EMPTY: "Boş: bölümde imaj yok (silinmiş).",
    WRITING: "Yazılıyor: güncelleme şu anda bu bölüme yazılıyor.",
    PENDING_VERIFY: "Doğrulama bekliyor: yeni imaj, ilk açılışta öz-testini geçmeli.",
    VALID: "Geçerli: imaj çalıştı ve kendini onayladı.",
    INVALID: "Geçersiz: imaj başarısız oldu, bir daha asla açılmaz.",
}

# The 8 steps of check_and_install() (device/ota_client.py), in Turkish.
UPDATE_STEPS_TR = [
    "Manifest indir",
    "İmza doğrula",
    "Sürüm kontrolü",
    "Boyut kontrolü",
    "Boş bölümü sil",
    "İndir + yaz",
    "Hash karşılaştır",
    "Önyükleme ayarla",
]


# ---------------------------------------------------------------------------
# Scenario texts (Turkish)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScenarioInfo:
    """Turkish description of one scenario."""

    name: str
    threat: str       # what the attacker / fault does
    defence: str      # which protection must stop it
    expected: str     # expected outcome (human text)
    expected_word: str


SCENARIO_INFO: dict[int, ScenarioInfo] = {
    1: ScenarioInfo(
        "Normal güncelleme (1.0.0 → 1.1.0)",
        "Saldırı yok. Üretici, imzalı yeni sürüm 1.1.0'ı yayınlıyor.",
        "Tüm kontroller: imza, sürüm, boyut, SHA-256 hash, ardından ilk açılışta öz-test.",
        "Kurulur, 1.1.0 açılır ve VALID olur; anti-rollback sayacı 1.1.0'a yükselir. "
        "Bölüm A'da 1.0.0 yedek olarak kalır.",
        INSTALLED,
    ),
    2: ScenarioInfo(
        "Aktarımda değiştirme – MITM",
        "Ağdaki saldırgan (sahte Wi-Fi, ele geçirilmiş router) gerçek 1.3.0 firmware'inin "
        "16 baytını indirme sırasında değiştiriyor. Manifest'e dokunamıyor, çünkü yeniden imzalayamaz.",
        "Cihaz yazarken SHA-256 hesaplar ve İMZALI manifest'teki hash ile karşılaştırır (adım 7).",
        "REJECTED (hash mismatch): boş bölüm silinir, cihaz 1.1.0'da kalır.",
        REJECTED,
    ),
    3: ScenarioInfo(
        "Sahte sunucu – yanlış anahtar",
        "Saldırgan kendi sunucusunu kurup kötü amaçlı '2.0.0' yayınlıyor. Manifest formatını biliyor "
        "ve doğru şekilde imzalıyor, ama KENDİ anahtarıyla (üreticinin gizli anahtarı imzalama makinesinden hiç çıkmaz).",
        "Cihaz yalnızca fabrikada gömülen açık anahtara güvenir → imza doğrulaması (adım 2).",
        "REJECTED (signature invalid): firmware'in tek baytı bile indirilmez.",
        REJECTED,
    ),
    4: ScenarioInfo(
        "Manifest sahteciliği (1.1.0 → 9.9.9)",
        "Saldırgan gerçek, imzalı 1.1.0 manifest'indeki sürümü 9.9.9 yapıyor, imzayı aynen bırakıyor. "
        "Amaç: zorla kurdurmak ya da anti-rollback sayacını 9.9.9'a itip gelecekteki tüm güncellemeleri engellemek.",
        "İmza; ad, sürüm, boyut ve hash alanlarının HEPSİNİ kapsar → tek alan değişse imza bozulur (adım 2).",
        "REJECTED (signature invalid): sayaç değişmez, cihaz 1.1.0'da kalır.",
        REJECTED,
    ),
    5: ScenarioInfo(
        "Geri düşürme / replay (1.0.0, 0.9.0)",
        "Saldırgan, bilinen açığı olan ESKİ ama GERÇEKTEN imzalı sürümleri (1.0.0 ve 0.9.0) tekrar sunuyor. "
        "İmzaları geçerli – tek başına imza kontrolü bunu durduramaz.",
        "Sürüm kontrolü (adım 3): yeni sürüm > mevcut sürüm VE ≥ min_allowed_version (anti-rollback sayacı).",
        "REJECTED (downgrade/replay): imza geçer ✅ ama sürüm kontrolünde durur.",
        REJECTED,
    ),
    6: ScenarioInfo(
        "İndirme kesintisi (%50)",
        "Bağlantı indirmenin yarısında kopuyor (zayıf Wi-Fi ya da cihazı yarım imajla bozmak isteyen saldırgan). "
        "Sunucu 65536 bayt duyuruyor ama 32768 bayttan sonra kesiyor.",
        "İmaj yalnızca PASİF bölüme yazılır; eksik indirme algılanır, yarım imaj silinir (adım 6).",
        "ABORTED: pasif bölüm silinir, cihaz 1.1.0'da çalışmaya devam eder.",
        ABORTED,
    ),
    7: ScenarioInfo(
        "Yazma sırasında güç kaybı",
        "1.3.0 yazılırken, imajın yarısında elektrik kesiliyor. Hiçbir temizlik kodu çalışamaz.",
        "A/B bölümleri: otadata hâlâ eski VALID bölümü gösterir. Açılışta bootloader yarım imajı siler.",
        "Cihaz yeniden açıldığında eski 1.1.0 ile çalışır; yarım yazılmış bölüm silinir.",
        POWER_LOSS,
    ),
    8: ScenarioInfo(
        "İmzalı ama öz-testte başarısız 1.2.0 → rollback",
        "Saldırı değil, hatalı sürüm: 1.2.0 gerçekten imzalı ve kurulur, ama sensör sürücüsü bozuk.",
        "İlk açılışta öz-test (PENDING_VERIFY). Başarısız → INVALID + otomatik geri dönüş.",
        "Kurulur, sonra otomatik ROLLBACK ile 1.1.0'a döner; 1.2.0 INVALID, sayaç YÜKSELMEZ.",
        ROLLBACK,
    ),
    9: ScenarioInfo(
        "İmzalı ama açılışta çöken 1.2.1 → rollback",
        "Aceleyle çıkarılmış 1.2.1 yaması, kendini onaylayamadan açılışta çöküyor.",
        "Watchdog cihazı yeniden başlatır; bootloader boot_attempts > 1 görür → otomatik geri dönüş.",
        "CRASH + ROLLBACK: cihaz 1.1.0'a döner, 1.2.1 INVALID olur.",
        ROLLBACK,
    ),
    10: ScenarioInfo(
        "Düzeltilmiş sürüm 1.3.0",
        "Saldırı yok. Hataları düzeltilmiş 1.3.0 yayınlanıyor.",
        "Tüm kontroller geçer, öz-test geçer → mark_app_valid().",
        "Kurulur ve VALID olur; anti-rollback sayacı 1.3.0'a yükselir.",
        INSTALLED,
    ),
}


def _served_release_dirs(ctx: SimContext, number: int) -> list[Path]:
    """Release folder(s) each scenario serves, in the order of its update attempts.

    Read from the attack modules' own constants, so it stays in sync with them.
    """
    r = ctx.release
    return {
        1: [r("1.1.0")],
        2: [r(tamper_in_transit.TARGET_VERSION)],
        3: [ctx.releases_dir / "_attacker" / fake_server_wrong_key.MALICIOUS_VERSION],
        4: [ctx.releases_dir / "_forged" / manifest_version_forgery.FORGED_VERSION],
        5: [r(v) for v in downgrade.OLD_VERSIONS],
        6: [r(interrupted_download.TARGET_VERSION)],
        7: [r("1.3.0")],
        8: [r("1.2.0")],
        9: [r("1.2.1")],
        10: [r("1.3.0")],
    }.get(number, [])


# ---------------------------------------------------------------------------
# Data recorded for the UI
# ---------------------------------------------------------------------------


@dataclass
class AttemptRecord:
    """One call of Device.check_update() observed during a run."""

    update: UpdateResult | None
    boot: BootResult | None
    power_loss: bool = False
    release_dir: Path | None = None
    manifest: dict | None = None

    @property
    def word(self) -> str:
        """INSTALLED / REJECTED / ABORTED / ROLLBACK / GÜÇ KAYBI"""
        if self.power_loss:
            return POWER_LOSS
        if self.boot is not None and self.boot.rolled_back:
            return ROLLBACK
        return self.update.status if self.update else "?"


@dataclass
class RunOutcome:
    """Everything the UI shows after running a scenario or a manual update."""

    title: str
    attempts: list[AttemptRecord] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)
    result: ScenarioResult | None = None     # scenarios only
    expected_word: str | None = None         # scenarios only
    prep_message: str | None = None
    error: str | None = None
    total_ms: float | None = None
    firmware_size: int = 0
    verify_ms: float | None = None

    @property
    def passed(self) -> bool | None:
        """Scenario verdict; None for a manual update (no expectation)."""
        if self.error:
            return False
        return self.result.passed if self.result else None

    @property
    def word(self) -> str:
        """Overall result word of the run."""
        if self.error:
            return "HATA"
        words = [a.word for a in self.attempts]
        for special in (ROLLBACK, POWER_LOSS):
            if special in words:
                return special
        return words[-1] if words else "?"

    @property
    def reason_tr(self) -> str:
        """Turkish reason for the overall result."""
        if self.error:
            return self.error
        if not self.attempts:
            return ""
        # the most interesting attempt: the first that did not simply install
        for a in self.attempts:
            if a.word != INSTALLED:
                return reason_tr(a)
        return reason_tr(self.attempts[-1])

    @property
    def raw_reason(self) -> str:
        """Original (English) reason from the device log."""
        return " | ".join(a.update.reason for a in self.attempts if a.update and a.update.reason)


# ---------------------------------------------------------------------------
# Interpreting results
# ---------------------------------------------------------------------------


def _failed_step(update: UpdateResult | None, power_loss: bool) -> int | None:
    """Number (1-8) of the step where the update stopped, or None if all passed."""
    if power_loss:
        return 6
    if update is None:
        return 1
    if update.status == INSTALLED:
        return None
    reason = update.reason
    checks = [
        (1, ("could not download manifest", "malformed manifest")),
        (2, ("signature invalid",)),
        (3, ("downgrade/replay",)),
        (4, ("does not fit in a slot",)),
        (7, ("hash mismatch", "size mismatch")),
        (6, ("connection lost", "incomplete download", "more data than")),
    ]
    for step, needles in checks:
        if any(n in reason for n in needles):
            return step
    return 1


def update_steps(record: AttemptRecord) -> list[tuple[str, str]]:
    """The 8 update steps with an icon each: ✅ passed / ❌ stopped here / ⏭️ not reached."""
    failed = _failed_step(record.update, record.power_loss)
    steps = []
    for number, label in enumerate(UPDATE_STEPS_TR, start=1):
        if failed is None or number < failed:
            icon = "✅"
        elif number == failed:
            icon = "❌"
        else:
            icon = "⏭️"
        steps.append((icon, f"{number}. {label}"))
    return steps


def failed_step(record: AttemptRecord) -> int | None:
    """Public wrapper: the step number where this attempt stopped (None = all passed)."""
    return _failed_step(record.update, record.power_loss)


def reason_tr(record: AttemptRecord) -> str:
    """Short Turkish explanation of an attempt's outcome."""
    upd, boot = record.update, record.boot
    if record.power_loss:
        return "güç kesildi; açılışta yarım imaj silindi, eski sürüm çalışıyor"
    if boot is not None and boot.rolled_back:
        if "CRASH" in boot.events:
            return f"açılışta çöktü (watchdog) → otomatik geri dönüş, çalışan: v{boot.version}"
        return f"öz-test başarısız → otomatik geri dönüş, çalışan: v{boot.version}"
    if upd is None:
        return "sonuç yok"
    if upd.status == INSTALLED:
        if boot is not None:
            return f"imza, sürüm ve hash doğrulandı; öz-test geçti, v{boot.version} {boot.state}"
        return "imza, sürüm ve hash doğrulandı"
    reason = upd.reason
    table = [
        ("signature invalid", "imza geçersiz (signature invalid)"),
        ("downgrade/replay", "eski sürüm / tekrar oynatma (downgrade/replay)"),
        ("hash mismatch", "hash uyuşmazlığı (hash mismatch) – firmware değiştirilmiş"),
        ("size mismatch", "boyut uyuşmazlığı (size mismatch)"),
        ("does not fit in a slot", "imaj bölüme sığmıyor (size check)"),
        ("connection lost", "bağlantı koptu – yarım imaj silindi"),
        ("incomplete download", "eksik indirme – yarım imaj silindi"),
        ("more data than", "sunucu manifest'ten fazla veri gönderdi"),
        ("could not download manifest", "manifest indirilemedi (sunucuya ulaşılamadı)"),
        ("malformed manifest", "bozuk manifest"),
    ]
    for needle, text in table:
        if needle in reason:
            return text
    return reason


def device_status(ctx: SimContext) -> dict:
    """otadata of the device (copy) - the source of the status panel."""
    return ctx.device.status()


# ---------------------------------------------------------------------------
# Running things
# ---------------------------------------------------------------------------

# One action at a time: the device flash and the log sinks are shared.
_ACTION_LOCK = threading.Lock()


class BusyError(RuntimeError):
    """Another action is still running."""


@contextmanager
def _exclusive() -> Iterator[None]:
    """Serialize actions (e.g. two quick clicks, or two browser tabs)."""
    if not _ACTION_LOCK.acquire(timeout=30):
        raise BusyError("Başka bir işlem hâlâ sürüyor, lütfen birkaç saniye sonra tekrar deneyin.")
    try:
        yield
    finally:
        _ACTION_LOCK.release()


@contextmanager
def capture_log() -> Iterator[list[str]]:
    """Collect every log line (without colors) written inside the block.

    Uses common.log's existing file-sink hook, so console output is unchanged.
    The list is filled when the block exits.
    """
    fd, name = tempfile.mkstemp(prefix="ota-ui-", suffix=".log")
    os.close(fd)
    path = Path(name)
    sink = log.add_file_sink(path)
    lines: list[str] = []
    try:
        yield lines
    finally:
        log.remove_file_sink(sink)
        try:
            lines.extend(path.read_text(encoding="utf-8").splitlines())
        finally:
            path.unlink(missing_ok=True)


@contextmanager
def record_attempts(ctx: SimContext) -> Iterator[list[AttemptRecord]]:
    """Record every Device.check_update() call (results + power loss) inside the block.

    The device's method is wrapped on the instance only and restored afterwards;
    behavior is unchanged (PowerLoss is re-raised).
    """
    records: list[AttemptRecord] = []
    device = ctx.device
    original = device.check_update

    def recording_check_update(server_url, power_loss_after=None):
        try:
            update, boot = original(server_url, power_loss_after=power_loss_after)
        except PowerLoss:
            records.append(AttemptRecord(update=None, boot=None, power_loss=True))
            raise
        records.append(AttemptRecord(update=update, boot=boot))
        return update, boot

    device.check_update = recording_check_update  # type: ignore[method-assign]
    try:
        yield records
    finally:
        del device.check_update   # back to the class method


def _read_manifest(release_dir: Path | None) -> dict | None:
    """Load a release's manifest.json for display (None if unavailable)."""
    if release_dir is None:
        return None
    try:
        return json.loads((Path(release_dir) / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _attach_manifests(records: list[AttemptRecord], release_dirs: list[Path]) -> None:
    """Pair each recorded attempt with the release folder it was served from."""
    for record, release_dir in zip(records, release_dirs):
        record.release_dir = release_dir
        record.manifest = _read_manifest(release_dir)


def _error_text(exc: BaseException) -> str:
    """Readable Turkish error message."""
    return f"Beklenmeyen hata: {exc.__class__.__name__}: {exc}"


# ---------------------------------------------------------------------------
# Context / device preparation
# ---------------------------------------------------------------------------


def _context_is_usable(keys_dir: Path, releases_dir: Path, flash_dir: Path, trusted_key_path: Path) -> bool:
    """True if keys, releases and device flash on disk belong together and can be reused."""
    try:
        public_key_path = keys_dir / "public_key.pem"
        if not (keys_dir / "private_key.pem").exists() or not public_key_path.exists():
            return False
        if not trusted_key_path.exists() or trusted_key_path.read_bytes() != public_key_path.read_bytes():
            return False
        public_key = load_public_key(public_key_path)
        for build in load_build_definitions():
            release = releases_dir / build["version"]
            if not (release / "firmware.bin").exists():
                return False
            manifest = parse_manifest((release / "manifest.json").read_bytes())
            if not verify_manifest(manifest, public_key):   # signed with an older key
                return False
        flash = Device(flash_dir, trusted_key_path).flash
        if not flash.is_formatted():
            return False
        otadata = flash.load_otadata()
        return otadata["slots"][otadata["active_slot"]]["state"] in (VALID, PENDING_VERIFY)
    except Exception:
        return False


def load_context(
    keys_dir: Path = KEYS_DIR,
    releases_dir: Path = RELEASES_DIR,
    flash_dir: Path = DEVICE_FLASH_DIR,
    trusted_key_path: Path = TRUSTED_KEY_PATH,
) -> tuple[SimContext, bool]:
    """Reuse the device on disk if everything is consistent, else factory-create it.

    Returns (ctx, created). Keys are generated automatically if missing
    (create_context -> ensure_keys).
    """
    with _exclusive():
        if _context_is_usable(keys_dir, releases_dir, flash_dir, trusted_key_path):
            ctx = SimContext(keys_dir=keys_dir, releases_dir=releases_dir, device=Device(flash_dir, trusted_key_path))
            return ctx, False
        return create_context(keys_dir, releases_dir, flash_dir, trusted_key_path), True


def factory_reset_new_context(
    keys_dir: Path = KEYS_DIR,
    releases_dir: Path = RELEASES_DIR,
    flash_dir: Path = DEVICE_FLASH_DIR,
    trusted_key_path: Path = TRUSTED_KEY_PATH,
) -> SimContext:
    """Sidebar button: keys (if missing) + freshly signed releases + device on 1.0.0."""
    with _exclusive():
        return create_context(keys_dir, releases_dir, flash_dir, trusted_key_path)


def _factory_reset(ctx: SimContext) -> None:
    """Device back to 1.0.0 using the existing releases (no re-signing)."""
    create_context(
        ctx.keys_dir,
        ctx.releases_dir,
        ctx.device.flash.root,
        ctx.device.trusted_key_path,
        build_releases=False,
    )


def ready_for(ctx: SimContext, number: int) -> bool:
    """Is the device in the starting state scenario `number` expects?"""
    try:
        status = ctx.device.status()
        version = ctx.device.current_version
        state = ctx.device.current_state
    except Exception:
        return False
    if state != VALID or any(s["state"] in (WRITING, PENDING_VERIFY) for s in status["slots"].values()):
        return False
    min_allowed = status["min_allowed_version"]
    if number == 1:
        return version == FACTORY_VERSION and min_allowed == FACTORY_VERSION
    if 2 <= number <= 9:
        return version == PREPARED_VERSION and min_allowed == PREPARED_VERSION
    # scenario 10 just needs a version below 1.3.0
    return version in (FACTORY_VERSION, PREPARED_VERSION) and compare_versions(min_allowed, version) <= 0


def prepare_for_scenario(ctx: SimContext, number: int) -> str | None:
    """Bring the device into the scenario's starting state. Returns a message if anything was done.

    Scenario 1 needs a factory-fresh 1.0.0; scenarios 2-9 need 1.1.0
    (factory reset + normal update, exactly like attacks/_standalone.py).
    """
    if ready_for(ctx, number):
        return None
    _factory_reset(ctx)
    if number == 1:
        return "Cihaz önce fabrika ayarlarına (1.0.0) döndürüldü"
    log.banner("Precondition: normal update 1.0.0 -> 1.1.0")
    result = scenario_1_normal_update(ctx)
    if not result.passed:
        raise RuntimeError(f"Cihaz 1.1.0'a hazırlanamadı: {result.actual}")
    return "Cihaz önce 1.1.0’a hazırlandı"


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def scenario_function(number: int) -> Callable[[SimContext], ScenarioResult]:
    """The scenario function with this number from demo.scenarios.SCENARIOS."""
    for n, _title, func in SCENARIOS:
        if n == number:
            return func
    raise KeyError(f"no scenario {number}")


def _run_one_scenario(ctx: SimContext, number: int) -> RunOutcome:
    """Run scenario `number` on the device as it is (no preparation, no lock)."""
    info = SCENARIO_INFO[number]
    outcome = RunOutcome(title=f"{number}. {info.name}", expected_word=info.expected_word)
    with capture_log() as lines:
        try:
            log.banner(f"Scenario {number}: {info.name}")
            with record_attempts(ctx) as records:
                result = scenario_function(number)(ctx)
            outcome.result = result
            outcome.attempts = records
            outcome.total_ms = result.update_ms
            outcome.firmware_size = result.firmware_size
            outcome.verify_ms = result.verify_ms
            _attach_manifests(records, _served_release_dirs(ctx, number))
            (log.ok if result.passed else log.fail)(
                "DEMO", f"Scenario {number} {'PASS' if result.passed else 'FAIL'}: {result.actual}"
            )
        except Exception as exc:
            outcome.error = _error_text(exc)
            log.fail("DEMO", f"Scenario {number} raised {exc!r}")
            log.raw(traceback.format_exc())
    outcome.log_lines = lines
    return outcome


def run_scenario(ctx: SimContext, number: int) -> RunOutcome:
    """Tab 1: prepare the device if needed, then run one scenario."""
    with _exclusive():
        prep_message = None
        prep_lines: list[str] = []
        try:
            with capture_log() as prep_lines:
                prep_message = prepare_for_scenario(ctx, number)
        except Exception as exc:
            info = SCENARIO_INFO[number]
            return RunOutcome(
                title=f"{number}. {info.name}",
                expected_word=info.expected_word,
                error=f"Hazırlık başarısız – {_error_text(exc)}",
                log_lines=prep_lines,
            )
        outcome = _run_one_scenario(ctx, number)
        outcome.prep_message = prep_message
        if prep_message:
            outcome.log_lines = prep_lines + ["", "-" * 78, ""] + outcome.log_lines
        return outcome


def available_releases(releases_dir: Path = RELEASES_DIR) -> list[str]:
    """Genuine releases in releases/ (attacker/forged folders excluded), sorted by version."""
    versions = []
    if releases_dir.exists():
        for child in releases_dir.iterdir():
            if child.is_dir() and not child.name.startswith("_") and (child / "manifest.json").exists():
                try:
                    compare_versions(child.name, "0.0.0")
                except Exception:
                    continue
                versions.append(child.name)
    from functools import cmp_to_key

    return sorted(versions, key=cmp_to_key(compare_versions))


def run_manual_update(
    ctx: SimContext, version: str, *, tamper: bool = False, cut_at: int | None = None
) -> RunOutcome:
    """Tab 2: serve one release (optionally tampered / cut) and let the device check it."""
    flags = []
    if tamper:
        flags.append("MITM")
    if cut_at:
        flags.append(f"{cut_at}. bayttan sonra kesinti")
    title = f"Elle güncelleme → v{version}" + (f" ({', '.join(flags)})" if flags else "")
    outcome = RunOutcome(title=title)
    with _exclusive(), capture_log() as lines:
        try:
            release_dir = ctx.release(version)
            if not (release_dir / "manifest.json").exists():
                raise FileNotFoundError(f"{release_dir} bulunamadı")
            log.banner(f"Manual update -> {version}" + (f" [{', '.join(flags)}]" if flags else ""))
            with record_attempts(ctx) as records:
                attempt = attempt_update(ctx, release_dir, tamper=tamper, cut_at=cut_at or None)
            _attach_manifests(records, [release_dir])
            outcome.attempts = records
            outcome.total_ms = attempt.total_ms
            outcome.firmware_size = attempt.update.firmware_size
            outcome.verify_ms = attempt.update.verify_ms
        except Exception as exc:
            outcome.error = _error_text(exc)
            log.fail("DEMO", f"Manual update raised {exc!r}")
            log.raw(traceback.format_exc())
    outcome.log_lines = lines
    return outcome


def run_all(ctx: SimContext, progress: Callable[[int, int, str], None] | None = None) -> list[RunOutcome]:
    """Tab 3: factory reset, then all scenarios in order on the same device (like the demo)."""
    outcomes: list[RunOutcome] = []
    with _exclusive():
        with capture_log():
            log.banner("Setup: factory-fresh device (v1.0.0)")
            _factory_reset(ctx)
        total = len(SCENARIOS)
        for index, (number, _title, _func) in enumerate(SCENARIOS):
            if progress:
                progress(index, total, SCENARIO_INFO[number].name)
            outcomes.append(_run_one_scenario(ctx, number))
        if progress:
            progress(total, total, "")
    return outcomes


def summary_row(outcome: RunOutcome, number: int) -> dict:
    """One row of the Tab 3 table (Turkish column names)."""
    info = SCENARIO_INFO[number]
    result = outcome.result
    return {
        "#": number,
        "Senaryo": info.name,
        "Beklenen": info.expected,
        "Gerçekleşen": f"{outcome.word} – {outcome.reason_tr}",
        "Sonuç": "✅" if outcome.passed else "❌",
        "Güncelleme süresi (ms)": round(result.update_ms, 1) if result and result.update_ms is not None else None,
        "Sonraki sürüm": result.version_after if result else "",
    }


def ms(value: float | None) -> str:
    """Format milliseconds for metrics."""
    return "–" if value is None else f"{value:.2f} ms"


def now_hms() -> str:
    """Current time as HH:MM:SS (shown next to results)."""
    return time.strftime("%H:%M:%S")
