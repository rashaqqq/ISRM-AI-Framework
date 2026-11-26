import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional


class ISRMDatabase:
    def __init__(self, db_path: str = "isrm_platform.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Asset_Inventory (
                    asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_name TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    confidentiality_score INTEGER NOT NULL CHECK (confidentiality_score BETWEEN 1 AND 5),
                    integrity_score INTEGER NOT NULL CHECK (integrity_score BETWEEN 1 AND 5),
                    availability_score INTEGER NOT NULL CHECK (availability_score BETWEEN 1 AND 5),
                    created_at TEXT NOT NULL
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Risk_Register (
                    risk_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    threat_cve_id TEXT NOT NULL,
                    model_used TEXT NOT NULL,
                    predicted_likelihood INTEGER NOT NULL CHECK (predicted_likelihood BETWEEN 1 AND 5),
                    predicted_impact INTEGER NOT NULL CHECK (predicted_impact BETWEEN 1 AND 5),
                    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 1 AND 25),
                    severity_class TEXT NOT NULL,
                    annex_a_controls TEXT NOT NULL,
                    treatment_action TEXT NOT NULL,
                    assessed_at TEXT NOT NULL,
                    FOREIGN KEY (asset_id) REFERENCES Asset_Inventory (asset_id) ON DELETE CASCADE
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS SoA_Report (
                    soa_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    risk_id INTEGER,
                    control_id TEXT NOT NULL,
                    control_title TEXT NOT NULL,
                    applicability_status TEXT NOT NULL,
                    justification_basis TEXT NOT NULL,
                    implementation_status TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (risk_id) REFERENCES Risk_Register (risk_id) ON DELETE SET NULL
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS RTP_Plan (
                    rtp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    risk_id INTEGER NOT NULL,
                    selected_treatment_option TEXT NOT NULL,
                    assigned_control TEXT NOT NULL,
                    target_completion_date TEXT NOT NULL,
                    residual_risk_score INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open',
                    FOREIGN KEY (risk_id) REFERENCES Risk_Register (risk_id) ON DELETE CASCADE
                );
            """)

            conn.commit()

    def seed_sample_assets_if_empty(self) -> None:
        with self._get_conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM Asset_Inventory").fetchone()[0]
            if count == 0:
                samples = [
                    ("Core Banking Database", "Database Server", "FinOps Lead", 5, 5, 5),
                    ("Active Directory Controller", "Identity Infrastructure", "IAM Team", 5, 5, 4),
                    ("Cloud IAM Server", "Cloud Security", "Cloud Architect", 5, 4, 4),
                    ("Customer Portal API", "Web Application", "Platform Engineering", 4, 4, 4),
                    ("Enterprise Backup Vault", "Storage & Backup", "Backup Admin", 4, 5, 5),
                ]
                now = datetime.utcnow().isoformat()
                conn.executemany(
                    """
                    INSERT INTO Asset_Inventory
                    (asset_name, asset_type, owner, confidentiality_score, integrity_score, availability_score, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [(*s, now) for s in samples],
                )
                conn.commit()

    def add_asset(
        self,
        asset_name: str,
        asset_type: str,
        owner: str,
        confidentiality_score: int,
        integrity_score: int,
        availability_score: int,
    ) -> int:
        now = datetime.utcnow().isoformat()
        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO Asset_Inventory
                (asset_name, asset_type, owner, confidentiality_score, integrity_score, availability_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    asset_name,
                    asset_type,
                    owner,
                    int(confidentiality_score),
                    int(integrity_score),
                    int(availability_score),
                    now,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def delete_asset(self, asset_id: int) -> None:
        with self._get_conn() as conn:
            conn.execute("DELETE FROM Asset_Inventory WHERE asset_id = ?", (int(asset_id),))
            conn.commit()

    def get_assets(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM Asset_Inventory ORDER BY asset_id DESC").fetchall()
            return [dict(r) for r in rows]

    def get_asset_by_id(self, asset_id: int) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM Asset_Inventory WHERE asset_id = ?", (int(asset_id),)).fetchone()
            return dict(row) if row else None

    def save_risk_assessment(
        self,
        asset_id: int,
        threat_cve_id: str,
        model_used: str,
        predicted_likelihood: int,
        predicted_impact: int,
        risk_score: int,
        severity_class: str,
        annex_a_controls: str,
        treatment_action: str,
        soa_records: List[Dict[str, Any]],
        rtp_records: List[Dict[str, Any]],
    ) -> int:
        now = datetime.utcnow().isoformat()
        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO Risk_Register
                (asset_id, threat_cve_id, model_used, predicted_likelihood, predicted_impact,
                 risk_score, severity_class, annex_a_controls, treatment_action, assessed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(asset_id),
                    threat_cve_id,
                    model_used,
                    int(predicted_likelihood),
                    int(predicted_impact),
                    int(risk_score),
                    severity_class,
                    annex_a_controls,
                    treatment_action,
                    now,
                ),
            )
            risk_id = int(cursor.lastrowid)

            for item in soa_records:
                conn.execute(
                    """
                    INSERT INTO SoA_Report
                    (risk_id, control_id, control_title, applicability_status,
                     justification_basis, implementation_status, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        risk_id,
                        item.get("control_id", "A.8.8"),
                        item.get("control_title", "Management of Technical Vulnerabilities"),
                        item.get("applicability_status", "Yes"),
                        item.get("justification_basis", "Automated ISO 27001 mapping"),
                        item.get("implementation_status", "Planned"),
                        now,
                    ),
                )

            for rtp in rtp_records:
                conn.execute(
                    """
                    INSERT INTO RTP_Plan
                    (risk_id, selected_treatment_option, assigned_control,
                     target_completion_date, residual_risk_score, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        risk_id,
                        rtp.get("selected_treatment_option", "Mitigate"),
                        rtp.get("assigned_control", annex_a_controls),
                        rtp.get("target_completion_date", "2026-12-15"),
                        int(rtp.get("residual_risk_score", max(1, risk_score // 3))),
                        rtp.get("status", "In Progress"),
                    ),
                )

            conn.commit()
            return risk_id

    def get_risk_register(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT
                    rr.*,
                    ai.asset_name,
                    ai.asset_type,
                    ai.owner
                FROM Risk_Register rr
                LEFT JOIN Asset_Inventory ai ON rr.asset_id = ai.asset_id
                ORDER BY rr.risk_score DESC, rr.risk_id DESC
            """).fetchall()
            return [dict(r) for r in rows]

    def get_soa_report(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT
                    s.*,
                    rr.threat_cve_id,
                    rr.risk_score,
                    ai.asset_name
                FROM SoA_Report s
                LEFT JOIN Risk_Register rr ON s.risk_id = rr.risk_id
                LEFT JOIN Asset_Inventory ai ON rr.asset_id = ai.asset_id
                ORDER BY s.soa_id DESC
            """).fetchall()
            return [dict(r) for r in rows]

    def get_rtp_plan(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT
                    rtp.*,
                    rr.threat_cve_id,
                    rr.predicted_likelihood,
                    rr.predicted_impact,
                    rr.risk_score,
                    rr.severity_class,
                    ai.asset_name
                FROM RTP_Plan rtp
                LEFT JOIN Risk_Register rr ON rtp.risk_id = rr.risk_id
                LEFT JOIN Asset_Inventory ai ON rr.asset_id = ai.asset_id
                ORDER BY rtp.rtp_id DESC
            """).fetchall()
            return [dict(r) for r in rows]