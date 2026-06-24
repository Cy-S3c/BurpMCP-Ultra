package com.burpmcp.ultra.injection

/**
 * Pure detection oracles for the injection probe — turn raw fuzz responses into
 * confirmed/likely findings:
 *  - SQL error signatures (DBMS fingerprint) for error-based SQLi
 *  - template math-evaluation for SSTI
 *  - file-content markers for path traversal / LFI
 *  - response-time delta for time-based (blind) SQLi / cmdi
 */
object InjectionOracle {

    private val sqlErrors: List<Pair<String, Regex>> = listOf(
        "mysql" to Regex("(?i)(SQL syntax.*MySQL|valid MySQL result|MySqlClient\\.|com\\.mysql\\.jdbc|MySQL server version)"),
        "postgresql" to Regex("(?i)(PostgreSQL.*ERROR|pg_query\\(\\)|PSQLException|org\\.postgresql|unterminated quoted string)"),
        "mssql" to Regex("(?i)(Microsoft SQL Server|ODBC SQL Server Driver|SQLServerException|Unclosed quotation mark after the character string)"),
        "oracle" to Regex("(?i)(ORA-[0-9]{5}|Oracle error|quoted string not properly terminated)"),
        "sqlite" to Regex("(?i)(SQLite/JDBCDriver|SQLite\\.Exception|sqlite3\\.OperationalError|\\[SQLITE_ERROR\\])")
    )

    /** Returns the DBMS whose error signature appears in [body], or null. Body is length-capped for safety. */
    fun sqlError(body: String): String? {
        val sample = body.take(200_000)
        return sqlErrors.firstOrNull { it.second.containsMatchIn(sample) }?.first
    }

    /** True if a unique math result [expected] (e.g. 1337*1337=1787569) appears — template/expression was evaluated. */
    fun evaluatedTo(body: String, expected: String): Boolean = body.contains(expected)

    /** Returns a file-read marker family if [body] looks like /etc/passwd or win.ini contents, else null. */
    fun fileMarker(body: String): String? = when {
        body.contains("root:x:0:0:") || Regex("root:[^:]*:0:0:").containsMatchIn(body.take(200_000)) -> "unix-passwd"
        body.contains("[fonts]", ignoreCase = true) || body.contains("[extensions]", ignoreCase = true) -> "windows-ini"
        else -> null
    }

    /**
     * True if [probeMs] is delayed relative to [baselineMs] by roughly the
     * injected sleep ([expectedDelaySec]). Uses a 0.7 slack factor to tolerate
     * jitter while rejecting normal responses.
     */
    fun timeDelayed(baselineMs: Long, probeMs: Long, expectedDelaySec: Int): Boolean {
        if (expectedDelaySec <= 0) return false
        val threshold = (expectedDelaySec * 1000L * 0.7).toLong()
        return (probeMs - baselineMs) >= threshold && probeMs >= threshold
    }
}
