"""
Live-demo web UI for the secure OTA simulation.

    streamlit run ui/app.py

All logic lives in ui/backend.py (which only drives the existing simulation);
this file only renders. Everything the audience sees is in Turkish.
"""

from __future__ import annotations

import html
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from demo.scenarios import SCENARIOS  # noqa: E402
from device.flash import EMPTY, INVALID, PENDING_VERIFY, VALID, WRITING  # noqa: E402
from device.ota_client import ABORTED, INSTALLED, REJECTED  # noqa: E402
from ui import backend  # noqa: E402

st.set_page_config(
    page_title="Güvenli OTA – Canlı Demo",
    page_icon="🔐",
    layout="wide",
)

BADGE_COLORS = {
    VALID: "#1e8e3e",
    INVALID: "#d93025",
    PENDING_VERIFY: "#e8710a",
    WRITING: "#1a73e8",
    EMPTY: "#80868b",
}

WORD_TR = {
    INSTALLED: "KURULDU",
    REJECTED: "REDDEDİLDİ",
    ABORTED: "İPTAL EDİLDİ",
    backend.ROLLBACK: "GERİ DÖNÜŞ",
    backend.POWER_LOSS: "GÜÇ KAYBI → ESKİ SÜRÜM",
}

st.markdown(
    """
    <style>
    .ota-badge {display:inline-block; padding:2px 10px; border-radius:999px;
                color:#fff; font-weight:600; font-size:0.85rem; letter-spacing:.02em;}
    .ota-steps {display:flex; flex-wrap:wrap; gap:6px; margin:4px 0 8px 0;}
    .ota-step {flex:1 1 120px; padding:8px 10px; border-radius:8px; font-size:0.9rem;
               border:1px solid rgba(128,128,128,.35);}
    .ota-step.ok   {background:rgba(30,142,62,.15);  border-color:rgba(30,142,62,.6);}
    .ota-step.fail {background:rgba(217,48,37,.18);  border-color:rgba(217,48,37,.8); font-weight:700;}
    .ota-step.skip {background:rgba(128,128,128,.08); opacity:.6;}
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def badge(state: str) -> str:
    """Colored HTML badge for an image state."""
    color = BADGE_COLORS.get(state, "#80868b")
    return f'<span class="ota-badge" style="background:{color}">{html.escape(state)}</span>'


def word_label(word: str) -> str:
    """'REJECTED (REDDEDİLDİ)'."""
    tr = WORD_TR.get(word)
    return f"{word} ({tr})" if tr and tr != word else word


def get_ctx():
    """The simulation context, kept in session_state so the device state carries over."""
    if "ctx" not in st.session_state:
        with st.spinner("Anahtarlar, imzalı sürümler ve cihaz hazırlanıyor..."):
            ctx, created = backend.load_context()
        st.session_state.ctx = ctx
        if created:
            st.session_state.notice = "İlk açılış: anahtarlar ve imzalı sürümler hazırlandı, cihaz 1.0.0'da."
    return st.session_state.ctx


def render_status(ctx) -> None:
    """'Cihaz durumu' panel: both slots + key counters."""
    st.subheader("📟 Cihaz durumu")
    try:
        status = backend.device_status(ctx)
    except Exception as exc:
        st.error(f"Cihaz durumu okunamadı: {exc}. Kenar çubuğundan fabrika ayarlarına döndürün.")
        return
    active = status["active_slot"]
    cols = st.columns(2)
    for col, slot in zip(cols, ("a", "b")):
        info = status["slots"][slot]
        if slot == active:
            role = "▶️ Çalışan / açılış bölümü"
        elif info["state"] == VALID:
            role = "↩️ Pasif – geri dönüş yedeği"
        else:
            role = "Pasif bölüm"
        version = f"v{info['version']}" if info.get("version") else "—"
        with col.container(border=True):
            st.markdown(f"#### Bölüm {slot.upper()}")
            st.markdown(
                f"Firmware: <b style='font-size:1.4rem'>{html.escape(version)}</b> &nbsp; {badge(info['state'])}"
                f"<br><span style='opacity:.8'>{role}</span>",
                unsafe_allow_html=True,
            )
    m1, m2, m3 = st.columns(3)
    running = status["slots"][active].get("version") or "—"
    m1.metric("Çalışan sürüm", f"v{running}")
    m2.metric("min_allowed_version (anti-rollback sayacı)", status["min_allowed_version"])
    m3.metric("boot_attempts", status["boot_attempts"])


def render_steps(record) -> None:
    """The 8-step update flow for one attempt, with ✅ / ❌ / ⏭️."""
    css = {"✅": "ok", "❌": "fail", "⏭️": "skip"}
    chips = "".join(
        f'<div class="ota-step {css[icon]}">{icon} {html.escape(label)}</div>'
        for icon, label in backend.update_steps(record)
    )
    st.markdown(f'<div class="ota-steps">{chips}</div>', unsafe_allow_html=True)

    stopped = backend.failed_step(record)
    boot = record.boot
    if record.power_loss:
        st.markdown(
            "⚡ **Adım 6 sırasında güç kesildi.** Yeniden açılışta bootloader yarım imajı sildi "
            "ve eski VALID bölümden açtı."
        )
    elif stopped is not None:
        st.markdown(f"🛡️ **Saldırı / hata adım {stopped}'de durduruldu** "
                    f"({backend.UPDATE_STEPS_TR[stopped - 1]}). Cihaz yeniden başlatılmadı.")
    elif boot is not None and boot.rolled_back:
        events = " → ".join(boot.events)
        st.markdown(f"🔁 **Yeniden başlatma:** `{events}` → otomatik geri dönüş, **v{boot.version}** çalışıyor.")
    elif boot is not None:
        st.markdown(f"🚀 **Yeniden başlatma:** öz-test geçti → **v{boot.version}** {boot.state} (mark_app_valid).")


def render_outcome(outcome) -> None:
    """Result box, step view, metrics, log and manifest of one run."""
    if outcome.prep_message:
        st.info(f"ℹ️ {outcome.prep_message}")

    reason = outcome.reason_tr
    if outcome.error:
        st.error(f"### ❌ Hata\n{outcome.error}")
    elif outcome.passed is True:
        st.success(
            f"### ✅ BAŞARILI – sistem beklendiği gibi davrandı\n"
            f"**Sonuç:** `{word_label(outcome.word)}` — {reason}"
        )
    elif outcome.passed is False:
        st.error(
            f"### ❌ BAŞARISIZ – beklenen davranış görülmedi\n"
            f"**Beklenen:** `{outcome.expected_word}` · **Gerçekleşen:** `{word_label(outcome.word)}` — {reason}"
        )
    else:  # manual update: no expectation, colour by outcome
        if outcome.word == INSTALLED:
            st.success(f"### ✅ Güncelleme kuruldu\n**Sonuç:** `{word_label(outcome.word)}` — {reason}")
        elif outcome.word == backend.ROLLBACK:
            st.warning(f"### 🔁 Kuruldu ama geri dönüldü\n**Sonuç:** `{word_label(outcome.word)}` — {reason}")
        else:
            verb = "iptal edildi" if outcome.word == ABORTED else "reddedildi"
            st.error(
                f"### 🛡️ Güncelleme {verb} – cihaz korundu\n**Sonuç:** `{word_label(outcome.word)}` — {reason}"
            )
    if outcome.raw_reason:
        st.caption(f"Cihaz logundaki neden: {outcome.raw_reason}")

    if outcome.attempts:
        st.markdown("##### Güncelleme akışı – saldırı nerede durduruldu?")
        for i, record in enumerate(outcome.attempts, start=1):
            if len(outcome.attempts) > 1:
                offered = record.manifest.get("version") if record.manifest else "?"
                st.markdown(f"**Deneme {i}: sunulan sürüm v{offered}**")
            render_steps(record)

    c1, c2, c3 = st.columns(3)
    c1.metric("İmza doğrulama süresi", backend.ms(outcome.verify_ms))
    c2.metric("Toplam güncelleme süresi", backend.ms(outcome.total_ms))
    c3.metric("Firmware boyutu", f"{outcome.firmware_size:,} bayt".replace(",", ".") if outcome.firmware_size else "–")

    with st.expander("Ayrıntılı log"):
        st.code("\n".join(outcome.log_lines) or "(log yok)", language="text")
    with st.expander("Manifest"):
        shown = False
        for i, record in enumerate(outcome.attempts, start=1):
            if record.manifest is not None:
                where = record.release_dir.relative_to(PROJECT_ROOT) if record.release_dir else ""
                label = f"Deneme {i} – " if len(outcome.attempts) > 1 else ""
                st.caption(f"{label}sunucunun gönderdiği manifest.json ({where})")
                st.json(record.manifest)
                shown = True
        if not shown:
            st.write("Manifest yok.")


def safe(action, *args, **kwargs):
    """Run a backend action; show a readable error instead of crashing."""
    try:
        return action(*args, **kwargs)
    except backend.BusyError as exc:
        st.warning(str(exc))
    except Exception as exc:  # never crash in front of the audience
        st.error(f"İşlem başarısız oldu: {exc.__class__.__name__}: {exc}")
    return None


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

st.title("Güvenli OTA Firmware Güncelleme – Canlı Demo")

try:
    ctx = get_ctx()
except Exception as exc:
    st.error(f"Simülasyon başlatılamadı: {exc.__class__.__name__}: {exc}")
    st.stop()

# ----------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("⚙️ Kontrol")
    if st.button("🏭 Cihazı fabrika ayarlarına döndür (1.0.0)", type="primary"):
        with st.spinner("Fabrika ayarlarına dönülüyor..."):
            new_ctx = safe(backend.factory_reset_new_context)
        if new_ctx is not None:
            st.session_state.ctx = ctx = new_ctx
            for key in ("tab1", "tab2", "tab3"):
                st.session_state.pop(key, None)
            st.success("Cihaz 1.0.0'a döndürüldü; sürümler yeniden imzalandı.")

    st.divider()
    st.subheader("Görüntü durumları")
    for state in (EMPTY, WRITING, PENDING_VERIFY, VALID, INVALID):
        st.markdown(f"{badge(state)}<br><small>{backend.STATE_LABELS_TR[state]}</small>", unsafe_allow_html=True)
    st.divider()
    st.caption("Bölüm = flash'taki A/B OTA bölümü (ESP32: ota_0 / ota_1).")

notice = st.session_state.pop("notice", None)
if notice:
    st.info(notice)

# The status panel is drawn at the END of the script (after any action ran),
# into this placeholder at the top of the page.
status_placeholder = st.empty()

tab1, tab2, tab3, tab4 = st.tabs(["🎯 Senaryo seç", "🛠️ Elle güncelleme", "📋 Tüm senaryolar", "❓ Nasıl çalışır?"])

# ----------------------------------------------------------------- tab 1
with tab1:
    numbers = [n for n, _t, _f in SCENARIOS]
    number = st.selectbox(
        "Senaryo",
        numbers,
        format_func=lambda n: f"{n}. {backend.SCENARIO_INFO[n].name}",
    )
    info = backend.SCENARIO_INFO[number]
    with st.container(border=True):
        st.markdown(f"**🎭 Saldırgan / hata ne yapıyor?** {info.threat}")
        st.markdown(f"**🛡️ Hangi koruma durdurmalı?** {info.defence}")
        st.markdown(f"**🎯 Beklenen sonuç:** {info.expected}")
    try:
        ready = backend.ready_for(ctx, number)
    except Exception:
        ready = False
    if not ready:
        needed = "fabrika ayarlarındaki 1.0.0" if number == 1 else "1.1.0"
        st.caption(f"ℹ️ Bu senaryo cihazın {needed} sürümünde olmasını bekliyor – çalıştırınca otomatik hazırlanacak.")

    if st.button("▶️ Saldırıyı / senaryoyu çalıştır", type="primary", key="run_scenario"):
        with st.spinner(f"Senaryo {number} çalışıyor..."):
            outcome = safe(backend.run_scenario, ctx, number)
        if outcome is not None:
            st.session_state.tab1 = outcome

    if "tab1" in st.session_state:
        st.divider()
        st.markdown(f"#### Son çalıştırma: {st.session_state.tab1.title}")
        render_outcome(st.session_state.tab1)

# ----------------------------------------------------------------- tab 2
with tab2:
    try:
        versions = backend.available_releases(ctx.releases_dir)
    except Exception:
        versions = []
    if not versions:
        st.warning("releases/ klasöründe sürüm bulunamadı. Kenar çubuğundan fabrika ayarlarına döndürün.")
    else:
        c1, c2, c3 = st.columns([1, 1, 1])
        default = versions.index("1.1.0") if "1.1.0" in versions else 0
        version = c1.selectbox("Sunucudaki sürüm (releases/)", versions, index=default)
        cut_at = c2.number_input(
            "Bağlantıyı şu bayttan sonra kes (--cut-at)",
            min_value=0,
            max_value=1024 * 1024,
            value=0,
            step=4096,
            help="0 = kapalı. Örnek: 32768 (64 KB'lık imajın yarısı).",
        )
        c3.markdown("&nbsp;")
        tamper = c3.checkbox("MITM: firmware’i boz (--tamper)")
        if st.button("🔍 Güncellemeyi kontrol et", type="primary", key="run_manual"):
            with st.spinner(f"v{version} deneniyor..."):
                outcome = safe(
                    backend.run_manual_update, ctx, version, tamper=tamper, cut_at=int(cut_at) or None
                )
            if outcome is not None:
                st.session_state.tab2 = outcome
    if "tab2" in st.session_state:
        st.divider()
        st.markdown(f"#### Son deneme: {st.session_state.tab2.title}")
        render_outcome(st.session_state.tab2)

# ----------------------------------------------------------------- tab 3
with tab3:
    st.write("Cihaz fabrika ayarlarına döner, ardından 10 senaryo aynı cihaz üzerinde sırayla çalışır "
             "(1.0.0 → 1.1.0 → … → 1.3.0).")
    if st.button("🚀 10 senaryonun hepsini çalıştır", type="primary", key="run_all"):
        bar = st.progress(0.0, text="Başlıyor...")

        def progress(done: int, total: int, name: str) -> None:
            text = f"Senaryo {done + 1}/{total}: {name}" if done < total else "Tamamlandı"
            bar.progress(done / total, text=text)

        outcomes = safe(backend.run_all, ctx, progress)
        if outcomes is not None:
            st.session_state.tab3 = outcomes

    if "tab3" in st.session_state:
        outcomes = st.session_state.tab3
        rows = [backend.summary_row(o, n) for o, (n, _t, _f) in zip(outcomes, SCENARIOS)]
        passed = sum(1 for o in outcomes if o.passed)
        summary = f"### {passed}/{len(outcomes)} senaryo başarılı"
        (st.success if passed == len(outcomes) else st.error)(summary)
        df = pd.DataFrame(rows)
        st.dataframe(df, hide_index=True)
        st.markdown("##### Senaryo başına güncelleme süresi (ms)")
        chart = pd.DataFrame(
            {"Güncelleme süresi (ms)": [r["Güncelleme süresi (ms)"] or 0 for r in rows]},
            index=[f"{r['#']:02d}" for r in rows],
        )
        st.bar_chart(chart)
        with st.expander("Tüm senaryoların logu"):
            st.code("\n".join(line for o in outcomes for line in o.log_lines), language="text")

# ----------------------------------------------------------------- tab 4
with tab4:
    st.markdown(
        """
### Mimari: üç taraf

**🔑 İmzalama makinesi (çevrimdışı)** → **🌐 Güvenilmez sunucu** → **📟 Cihaz (ESP32)**

1. **İmzalama makinesi** firmware'i derler, SHA-256 hash'ini hesaplar ve *manifest*'i
   (ad, sürüm, boyut, hash) **ECDSA P-256** gizli anahtarıyla imzalar. Gizli anahtar bu makineden hiç çıkmaz.
2. **Sunucu** sadece `manifest.json` ve `firmware.bin` dosyalarını dağıtır. Sır tutmaz;
   ele geçirilse ya da araya biri girse bile güvenlik bozulmaz.
3. **Cihaz** fabrikada gömülen **açık anahtarla** imzayı doğrular, sürümü kontrol eder,
   indirirken hash'i hesaplar ve imzalı hash ile karşılaştırır.

### Güvenlik ağdan değil, imzadan gelir
Kanal düz HTTP'dir – bilerek. Saldırgan ağı kontrol etse bile geçerli bir imza üretemez:
değiştirilmiş firmware → **hash uyuşmazlığı**, değiştirilmiş manifest veya yanlış anahtar → **imza geçersiz**,
eski imzalı sürüm → **sürüm kontrolü / anti-rollback sayacı**.

### 8 adım (sıra önemli!)
1 manifest indir → 2 **imza doğrula** → 3 sürüm kontrolü → 4 boyut kontrolü →
5 boş bölümü sil → 6 indir + yaz → 7 **hash karşılaştır** → 8 önyükleme ayarla

### A/B + rollback – tek cümle
Yeni sürüm her zaman **pasif** bölüme yazılır ve `PENDING_VERIFY` olarak açılır; öz-testi geçerse `VALID` olur,
geçemez ya da çökerse bootloader otomatik olarak eski `VALID` bölüme **geri döner** – cihaz asla tuğlaya dönmez.
"""
    )

# ----------------------------------------------------------------- status (top of page)
with status_placeholder.container():
    render_status(st.session_state.get("ctx", ctx))
    st.divider()
