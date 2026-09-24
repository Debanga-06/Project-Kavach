# Security Notes

## SQL Injection Protection

**Status: Protected by default — verified in Step 2.**

All database access goes through SQLAlchemy's ORM query API
(`db.query(Model).filter(...)`, `db.get(Model, id)`, `session.add(obj)`).
These always send user input as **bound parameters**, never as
string-concatenated SQL — so injection isn't possible through them.

Verified with live payloads against `/auth/register` and `/auth/login`:
- `a@a.com' OR '1'='1` as email → rejected by Pydantic `EmailStr` validation (422)
- `x@x.com'; DROP TABLE users; --` as email → rejected by Pydantic validation (422)
- `pass' OR '1'='1` as password → accepted, but only ever treated as a literal
  string (hashed by Argon2, stored as a hash). No SQL was executed from it.

### Rule going forward

As we add the URL/email/file/secret scanners and their DB writes:

1. **Never** build queries with f-strings / `.format()` / `%` on user input
   (e.g. `f"SELECT * FROM scans WHERE target = '{url}'"` is forbidden).
2. Always use the ORM (`db.query(...)`) or, if raw SQL is ever unavoidable,
   SQLAlchemy's `text()` with **bound parameters**:
   ```python
   # OK — parameterized
   db.execute(text("SELECT * FROM scans WHERE target = :target"), {"target": url})

   # NEVER — string interpolation
   db.execute(f"SELECT * FROM scans WHERE target = '{url}'")
   ```
3. All request bodies are validated by Pydantic schemas before touching the
   DB layer (as already done for `UserRegister`/`UserLogin`), which adds a
   second layer of input filtering.

This satisfies the SQL Injection item under TRD §15 "Security Tests".
