"""MariaDB adapter for the proposed-action approval service."""

import json
from datetime import UTC

from .approval import ApprovalError, Decision, ProposedAction


class DatabaseApprovalRepository:
    """Persist lifecycle transitions with compare-and-set updates."""

    def _connection(self):
        from .. import db

        conn = db.get_connection()
        cursor = conn.cursor(dictionary=True)
        db._ensure_analysis_schema(cursor)
        return conn, cursor

    @staticmethod
    def _from_row(row) -> ProposedAction:
        for key in ("proposed_at", "expires_at", "decided_at", "executed_at"):
            value = row.get(key)
            if value is not None and value.tzinfo is None:
                row[key] = value.replace(tzinfo=UTC)
        row["arguments"] = json.loads(row["arguments"] or "{}")
        row["requires_approval"] = bool(row["requires_approval"])
        return ProposedAction.model_validate(row)

    @staticmethod
    def _database_time(value):
        return value.astimezone(UTC).replace(tzinfo=None) if value else None

    @staticmethod
    def _record_event(cursor, action_id, status, actor, reason):
        cursor.execute(
            """INSERT INTO proposed_action_events
               (action_id, status, actor, reason, occurred_at)
               VALUES (%s, %s, %s, %s, UTC_TIMESTAMP(6))""",
            (action_id, status, actor, reason),
        )

    def create(self, action: ProposedAction) -> ProposedAction:
        conn, cursor = self._connection()
        try:
            cursor.execute(
                """INSERT INTO proposed_actions
                   (id, session_id, name, arguments, target, rationale, risk,
                    requires_approval, status, actor, reason, proposed_at,
                    expires_at, decided_at, executed_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s, %s, %s)""",
                (
                    action.id,
                    action.session_id,
                    action.name,
                    json.dumps(action.arguments),
                    action.target,
                    action.rationale,
                    action.risk,
                    action.requires_approval,
                    action.status,
                    action.actor,
                    action.reason,
                    self._database_time(action.proposed_at),
                    self._database_time(action.expires_at),
                    self._database_time(action.decided_at),
                    self._database_time(action.executed_at),
                ),
            )
            self._record_event(cursor, action.id, "proposed", "ai", "")
            if action.status == "approved":
                self._record_event(
                    cursor, action.id, "approved", action.actor, action.reason
                )
            conn.commit()
            return action
        finally:
            cursor.close()
            conn.close()

    def get(self, action_id: str) -> ProposedAction | None:
        conn, cursor = self._connection()
        try:
            cursor.execute("SELECT * FROM proposed_actions WHERE id = %s", (action_id,))
            row = cursor.fetchone()
            return self._from_row(row) if row else None
        finally:
            cursor.close()
            conn.close()

    def decide(
        self, action_id: str, decision: Decision, actor: str, reason: str
    ) -> ProposedAction:
        conn, cursor = self._connection()
        try:
            cursor.execute(
                """UPDATE proposed_actions
                   SET status = %s, actor = %s, reason = %s,
                       decided_at = UTC_TIMESTAMP()
                   WHERE id = %s AND status = 'proposed'""",
                (decision, actor, reason, action_id),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                raise ApprovalError("action was already decided or does not exist")
            self._record_event(cursor, action_id, decision, actor, reason)
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        return self.get(action_id)

    def expire(self, action_id: str) -> ProposedAction:
        conn, cursor = self._connection()
        try:
            cursor.execute(
                """UPDATE proposed_actions
                   SET status = 'expired', actor = 'system',
                       reason = 'approval request expired', decided_at = UTC_TIMESTAMP()
                   WHERE id = %s AND status = 'proposed'""",
                (action_id,),
            )
            if cursor.rowcount == 1:
                self._record_event(
                    cursor,
                    action_id,
                    "expired",
                    "system",
                    "approval request expired",
                )
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        return self.get(action_id)

    def claim_execution(self, action_id: str) -> bool:
        conn, cursor = self._connection()
        try:
            cursor.execute(
                """UPDATE proposed_actions SET status = 'executing'
                   WHERE id = %s AND status = 'approved'""",
                (action_id,),
            )
            claimed = cursor.rowcount == 1
            if claimed:
                self._record_event(cursor, action_id, "executing", "system", "")
            conn.commit()
            return claimed
        finally:
            cursor.close()
            conn.close()

    def finish_execution(
        self, action_id: str, *, succeeded: bool, reason: str = ""
    ) -> ProposedAction:
        status = "executed" if succeeded else "failed"
        conn, cursor = self._connection()
        try:
            cursor.execute(
                """UPDATE proposed_actions
                   SET status = %s, reason = %s, executed_at = UTC_TIMESTAMP()
                   WHERE id = %s AND status = 'executing'""",
                (status, reason, action_id),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                raise ApprovalError("action was not claimed for execution")
            self._record_event(cursor, action_id, status, "system", reason)
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        return self.get(action_id)

    def list_for_session(self, session_id: int) -> list[ProposedAction]:
        conn, cursor = self._connection()
        try:
            cursor.execute(
                """SELECT * FROM proposed_actions
                   WHERE session_id = %s ORDER BY proposed_at""",
                (session_id,),
            )
            return [self._from_row(row) for row in cursor.fetchall()]
        finally:
            cursor.close()
            conn.close()


def get_approval_service():
    from .approval import ApprovalService

    return ApprovalService(DatabaseApprovalRepository())
