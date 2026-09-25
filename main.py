import os
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

import pandas as pd
import requests
import streamlit as st

# Konfigurasi Tampilan Halaman
st.set_page_config(
    page_title="FASIH Bulk Action - Pengawas/PML",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_URL = "https://fasih-sm.bps.go.id"
DEFAULT_PERIOD = "fd68e454-ba45-4b85-8205-f3bf777ded24"
EP_APPROVAL = "/app/api/assignment-approval/api/v2/approval"
EP_REVOKE = "/app/api/assignment-approval/api/v2/revoke-approval"
EP_STATUS = "/app/api/assignment-general/api/assignment/get-by-assignment-id"
EP_MYINFO = "/app/api/survey/api/v1/users/myinfo"

ACTIONS = {
    "reject": (EP_APPROVAL, "false", "Reject"),
    "approve": (EP_APPROVAL, "true", "Approve"),
    "revoke": (EP_REVOKE, "false", "Revoke"),
    "cek": (EP_STATUS, None, "Cek Status"),
}

DEFAULT_SKIP = {
    "reject": ["REJECT", "SUBMITTED"],
    "approve": ["APPROVED", "REJECT"],
    "revoke": [],
    "cek": [],
}

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


# ==========================================
# Fungsi Jaringan & Sesi FASIH
# ==========================================
def make_session(base_url: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Referer": f"{base_url}/app/",
        "Origin": base_url,
    })
    return s


def load_cookies(session: requests.Session, cookie_str: str, base_url: str):
    session.cookies.clear()
    host = urlparse(base_url).hostname
    cookie_str = re.sub(r"^\s*cookie:\s*", "", cookie_str, flags=re.I)
    for part in cookie_str.replace("\n", " ").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        session.cookies.set(k.strip(), v.strip(), domain=host, path="/")


def get_xsrf(session: requests.Session):
    token = None
    for c in session.cookies:
        if c.name == "XSRF-TOKEN":
            token = unquote(c.value)
    return token


def call(session, base_url, method, path, payload=None, params=None):
    token = get_xsrf(session)
    if not token:
        raise Exception("XSRF-TOKEN tidak ada di cookie. Pastikan cookie valid.")
    r = session.request(
        method,
        base_url + path,
        json=payload,
        params=params,
        headers={"X-XSRF-TOKEN": token, "Cache-Control": "no-cache"},
        timeout=30,
    )
    try:
        body = r.json()
    except Exception:
        body = {}
    return r.status_code, body


def check_role(session, base_url, period_id):
    code, body = call(
        session,
        base_url,
        "GET",
        EP_MYINFO,
        params={"surveyPeriodId": period_id},
    )
    if code != 200 or not body.get("success") or not body.get("data"):
        raise Exception(f"HTTP {code}: {body.get('message', 'Sesi login tidak valid')}")
    u = body["data"]
    role = u.get("surveyRole") or {}
    desc = role.get("description") or role.get("name") or "?"
    name = u.get("fullname") or u.get("username") or "?"
    norm = f"{role.get('description', '')} {role.get('name', '')}".lower()
    allowed = any(k in norm for k in ("admin", "pengawas", "pml", "pemeriksa"))
    return name, desc, allowed


def process_one(session, base_url, action, assignment_id, max_retries=2):
    last_note, kind = "", None
    for attempt in range(max_retries + 1):
        try:
            if action == "cek":
                code, res = call(
                    session,
                    base_url,
                    "GET",
                    EP_STATUS,
                    params={"assignmentId": assignment_id},
                )
            else:
                ep, status_approval, _ = ACTIONS[action]
                payload = {
                    "assignmentId": assignment_id,
                    "statusApproval": status_approval,
                    "comment": '{"dataKey":"","notes":[]}',
                }
                code, res = call(session, base_url, "POST", ep, payload=payload)
        except Exception as e:
            last_note = f"Jaringan: {e}"
            if attempt < max_retries:
                time.sleep(2)
                continue
            return False, last_note, "network", None

        msg = res.get("message") if isinstance(res, dict) else None
        if (
            code == 200
            and isinstance(res, dict)
            and res.get("success")
            and res.get("data")
        ):
            d = res["data"]
            if action == "cek":
                return (
                    True,
                    f"Status: [{d.get('assignment_status_alias', 'UNKNOWN')}] | "
                    f"Identitas: {d.get('code_identity', '-')}",
                    None,
                    d,
                )
            return (
                True,
                f"Status: {d.get('assignmentStatusAlias', 'Success')}",
                None,
                d,
            )

        last_note = msg or f"HTTP {code}"
        if code == 429 or "rate limit" in str(last_note).lower():
            time.sleep(4 * (attempt + 1))
        elif code in (401, 403, 419) or re.search(
            r"token|session|sesi|login|unauthorized", str(last_note), re.I
        ):
            return False, f"Sesi kedaluwarsa ({last_note})", "auth", None
        elif code in (502, 503, 504):
            time.sleep(2)
        else:
            return False, last_note, "biz", None

    return False, last_note, kind, None


def handle_id(session, base_url, action, aid, skip_kw, precheck):
    prev = ""
    if action != "cek" and precheck:
        ok, note, kind, data = process_one(session, base_url, "cek", aid)
        if not ok:
            if kind == "biz":
                return (
                    "skip",
                    f"Tidak ditemukan / tidak bisa diakses: {note}",
                    None,
                )
            return "fail", f"Pra-cek gagal: {note}", kind
        alias = (
            (data.get("assignment_status_alias") or "").upper() if data else ""
        )
        if any(k in alias for k in skip_kw):
            return "skip", f"Sudah berstatus [{alias}]", None
        prev = f" (sebelumnya [{alias}])"

    ok, note, kind, _ = process_one(session, base_url, action, aid)
    return ("ok" if ok else "fail"), note + (prev if ok else ""), kind


# ==========================================
# Fungsi Baca ID dari File Unggahan
# ==========================================
def extract_ids_from_file(uploaded_file):
    filename = uploaded_file.name.lower()
    raw_items = []
    if filename.endswith((".xlsx", ".xls")):
        df = pd.read_excel(uploaded_file)
        target_col = None
        for col in df.columns:
            clean_c = str(col).lower().replace("_", " ").strip()
            if clean_c in ["link fasih", "assignment id", "id assignment", "id"]:
                target_col = col
                break
        if target_col:
            raw_items = df[target_col].dropna().astype(str).tolist()
        else:
            for col in df.columns:
                col_vals = df[col].dropna().astype(str).tolist()
                if any(UUID_RE.search(x) for x in col_vals):
                    raw_items = col_vals
                    break
            if not raw_items and len(df.columns) > 0:
                raw_items = df.iloc[:, 0].dropna().astype(str).tolist()
    elif filename.endswith(".csv"):
        df = pd.read_csv(uploaded_file)
        target_col = None
        for col in df.columns:
            clean_c = str(col).lower().replace("_", " ").strip()
            if clean_c in ["link fasih", "assignment id", "id assignment", "id"]:
                target_col = col
                break
        if target_col:
            raw_items = df[target_col].dropna().astype(str).tolist()
        else:
            raw_items = df.iloc[:, 0].dropna().astype(str).tolist()
    else:
        text = uploaded_file.read().decode("utf-8-sig", errors="ignore")
        raw_items = re.split(r"[\s,;]+", text)

    seen = set()
    cleaned_ids = []
    for item in raw_items:
        s = str(item).strip()
        m = UUID_RE.search(s)
        val = m.group(0) if m else s
        if val and val not in seen and val.lower() != "nan":
            seen.add(val)
            cleaned_ids.append(val)
    return cleaned_ids


# ==========================================
# Tampilan Sidebar (Konfigurasi & Akun)
# ==========================================
with st.sidebar:
    st.header("⚙️ Pengaturan Akun")

    cookie_file_path = Path("cookie.txt")
    default_cookie = (
        cookie_file_path.read_text(encoding="utf-8").strip()
        if cookie_file_path.exists()
        else ""
    )

    cookie_input = st.text_area(
        "Cookie FASIH",
        value=default_cookie,
        height=150,
        placeholder="Tempel seluruh nilai cookie dari browser di sini...",
        help="Buka FASIH di Chrome/Edge -> F12 -> tab Network -> klik salah satu baris fasih-sm -> Request Headers -> salin nilai Cookie.",
    )

    if cookie_input.strip() and cookie_input.strip() != default_cookie:
        cookie_file_path.write_text(cookie_input.strip(), encoding="utf-8")

    period_id = st.text_input(
        "Survey Period ID",
        value=DEFAULT_PERIOD,
        help="ID periode sensus/survei. Biarkan default untuk Sensus Ekonomi 2026.",
    )

    delay = st.slider(
        "Jeda per request (detik)",
        min_value=0.2,
        max_value=2.0,
        value=0.6,
        step=0.1,
    )

    if st.button("🔍 Verifikasi Status Login"):
        if not cookie_input.strip():
            st.error("Silakan tempel cookie terlebih dahulu.")
        else:
            with st.spinner("Memeriksa sesi login FASIH..."):
                s = make_session(BASE_URL)
                load_cookies(s, cookie_input.strip(), BASE_URL)
                try:
                    name, role_desc, is_allowed = check_role(
                        s, BASE_URL, period_id
                    )
                    st.success(
                        f"**Terhubung!**\n\nNama: `{name}`\n\nRole: `{role_desc}`"
                    )
                    if not is_allowed:
                        st.warning(
                            "Akun ini bukan role Admin/Pengawas/PML. Aksi Approve mungkin akan ditolak server."
                        )
                except Exception as e:
                    st.error(f"Gagal login: {e}")

# ==========================================
# Area Utama Aplikasi
# ==========================================
st.title("⚡ FASIH Bulk Action")
st.caption(
    "Alat bantu persetujuan (Approve) atau penolakan (Reject) massal assignment FASIH SM tanpa klik satu per satu."
)

col_aksi, col_opsi = st.columns([1, 1])

with col_aksi:
    action_choice = st.selectbox(
        "Pilih Aksi yang Akan Dijalankan",
        options=["reject", "approve", "cek", "revoke"],
        format_func=lambda x: {
            "reject": "1. Reject Massal",
            "approve": "2. Approve Massal (Pengawas/PML)",
            "cek": "3. Cek Status Saja (Aman)",
            "revoke": "4. Revoke Approval",
        }[x],
    )

with col_opsi:
    st.write("**Opsi Pengamanan:**")
    dry_run = st.checkbox(
        "Mode Simulasi (Dry Run)",
        value=False,
        help="Hanya membaca file dan rencana tanpa mengirim data ke server FASIH.",
    )
    precheck = st.checkbox(
        "Pra-cek status assignment sebelum eksekusi",
        value=True,
        help="Otomatis melewati assignment yang sudah berstatus sesuai (misal: melewati yang sudah REJECT/APPROVED).",
    )

st.divider()

# Input File
uploaded_file = st.file_uploader(
    "Unggah Daftar Assignment (.xlsx, .csv, atau .txt)",
    type=["xlsx", "xls", "csv", "txt"],
    help="Pastikan ada kolom bernama 'Link Fasih' atau 'Assignment ID'. Link lengkap assignment juga otomatis diekstrak.",
)

if uploaded_file is not None:
    ids = extract_ids_from_file(uploaded_file)
    if not ids:
        st.error(
            "Tidak ditemukan UUID atau link assignment yang valid di dalam file tersebut."
        )
    else:
        st.success(f"Ditemukan **{len(ids)}** Assignment unik.")

        with st.expander("Lihat 5 contoh ID teratas yang terbaca"):
            st.write(ids[:5])

        # Tombol Eksekusi
        label_btn = (
            f"Jalankan Simulasi {action_choice.upper()}"
            if dry_run
            else f"Mulai Proses {action_choice.upper()} Sekarang"
        )
        warna_tipe = "secondary" if dry_run else "primary"

        if st.button(label_btn, type=warna_tipe):
            if not cookie_input.strip():
                st.error(
                    "Cookie FASIH wajib diisi di panel samping kiri sebelum memproses."
                )
            else:
                session = make_session(BASE_URL)
                load_cookies(session, cookie_input.strip(), BASE_URL)

                # Validasi peran
                with st.spinner("Memvalidasi hak akses akun..."):
                    try:
                        acc_name, acc_role, allowed = check_role(
                            session, BASE_URL, period_id
                        )
                        if not allowed and action_choice != "cek":
                            st.error(
                                f"Role akun '{acc_role}' tidak memiliki wewenang untuk aksi ini."
                            )
                            st.stop()
                    except Exception as err:
                        st.error(
                            f"Koneksi gagal atau Cookie sudah kedaluwarsa: {err}"
                        )
                        st.stop()

                # Mulai Loop Proses
                progress_bar = st.progress(0)
                status_placeholder = st.empty()
                log_placeholder = st.empty()

                results = []
                ok_n = fail_n = skip_n = 0
                skip_kw = DEFAULT_SKIP.get(action_choice, [])
                total_data = len(ids)

                for idx, aid in enumerate(ids):
                    status_placeholder.text(
                        f"Memproses {idx + 1} dari {total_data}: {aid}..."
                    )

                    if dry_run:
                        state, note = (
                            "skip",
                            "Simulasi aktif (tidak ada request dikirim)",
                        )
                    else:
                        state, note, _ = handle_id(
                            session,
                            BASE_URL,
                            action_choice,
                            aid,
                            skip_kw,
                            precheck,
                        )

                    waktu_skrg = datetime.now().strftime("%H:%M:%S")

                    if state == "ok":
                        ok_n += 1
                        stt = "Berhasil"
                    elif state == "skip":
                        skip_n += 1
                        stt = "Dilewati"
                    else:
                        fail_n += 1
                        stt = "Gagal"

                    results.append({
                        "Waktu": waktu_skrg,
                        "Assignment ID": aid,
                        "Aksi": action_choice.upper(),
                        "Status": stt,
                        "Keterangan": note,
                    })

                    # Update tampilan berkala
                    progress_bar.progress((idx + 1) / total_data)
                    df_current = pd.DataFrame(results)
                    log_placeholder.dataframe(
                        df_current.tail(10), use_container_width=True
                    )

                    if not dry_run and idx + 1 < total_data:
                        time.sleep(delay)

                status_placeholder.success("🎉 Pemrosesan Selesai!")

                # Kartu Ringkasan
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total ID", total_data)
                c2.metric("Berhasil", ok_n)
                c3.metric("Dilewati", skip_n)
                c4.metric("Gagal", fail_n)

                # Tabel Hasil Lengkap & Download
                df_all = pd.DataFrame(results)
                st.subheader("Laporan Hasil Eksekusi")
                st.dataframe(df_all, use_container_width=True)

                csv_data = df_all.to_csv(index=False).encode("utf-8-sig")
                st.download_button(
                    label="📥 Unduh File Log (CSV)",
                    data=csv_data,
                    file_name=f"log_{action_choice}_{datetime.now():%Y%m%d_%H%M%S}.csv",
                    mime="text/csv",
                )