"""Static fixtures used by tests and by the offline UI mock mode."""
from __future__ import annotations

LAB_WORDLIST = [
    "password", "123456", "admin", "letmein", "qwerty",
    "worldmonitor", "monitor123", "Sunshine2019!", "Spring2024!", "P@ssw0rd",
]

RATE_LIMIT_TARGET = "a.reyes"

SAMPLE_LOG_LINES = [
    {"level": "info",  "ts": "2025-03-11T02:31:19Z", "msg": "auth.login.attempt",
     "fields": {"username": "a.reyes", "password": "Sunshine2019!",
                "sourceIp": "45.155.204.11"}},
    {"level": "info",  "ts": "2025-03-11T02:31:22Z", "msg": "auth.login.success",
     "fields": {"username": "a.reyes", "email": "a.reyes@worldmonitor.example",
                "ssn": "412-88-7391",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"}},
    {"level": "error", "ts": "2025-03-11T03:10:04Z", "msg": "api.monitor.read.failed",
     "fields": {"monitorId": "wm-1004", "actor": "m.okafor",
                "error": 'SequelizeDatabaseError: relation "monitors" does not exist',
                "stack": "at Query.run (/app/src/controllers/monitorController.js:118:22)",
                "apiKey": "wmk_live_1a77fe0b93d24c6e8f10"}},
    {"level": "info",  "ts": "2025-03-11T04:00:00Z", "msg": "payment.method.added",
     "fields": {"customer": "Northwind Trading BV",
                "cardNumber": "4111 1111 1111 1111", "cvv": "737"}},
]