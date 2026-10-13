# Detection Rules

SentinelSOC ships with two rules for authentication logs. Both only look at events
whose `event_type` is `login` and whose `status` is `success` or `failure`
(see [architecture.md](architecture.md) for how logs are normalised).

All thresholds can be changed in the dashboard sidebar or with command-line options.

| Rule | Name | Default settings |
|------|------|------------------|
| SOC-001 | Repeated failed logins | 5 failures within 10 minutes |
| SOC-002 | Successful login after repeated failures | 3 failures within the 30 minutes before the success |

---

## SOC-001 - Repeated failed logins

**Question it answers:** is someone guessing passwords?

**Logic**

1. Keep only failed logins.
2. Group them. Two modes are available (setting *Count failures per*):
   * `account_and_source` (default): one group per *(source IP, username)*. Finds
     repeated guessing against one account from one place.
   * `source`: one group per *source IP*. Also finds one source trying many accounts
     (for example password spraying), which the default mode misses.
3. Inside each group, slide a window of `failure_window_minutes` over the events.
   A window that holds at least `failure_threshold` failures qualifies. The window
   boundary is inclusive: failures exactly 10 minutes apart count as inside a
   10-minute window.
4. Overlapping qualifying windows are merged, so one continuous attack produces
   **one alert** that lists every failure involved.

**Severity**

| Failures in the burst | Severity |
|-----------------------|----------|
| at least the threshold | Medium |
| at least 2 x the threshold | High |

**Evidence:** failure count, targeted account(s), source IP, first and last failure,
the rule settings that fired, and the services and hosts involved. The alert also
lists the IDs of every event it is based on.

**Likely false positives:** users who forgot a password, expired credentials in a
saved session or mobile mail app, shared NAT addresses where many users appear to
come from one IP (mainly in `source` mode), and misconfigured service accounts.

**Recommended response (shown in the alert):** confirm whether the activity is
expected; if not, block or rate-limit the source, review other logs from the same
source, consider a temporary account lockout, and require multi-factor authentication.

**MITRE ATT&CK**

| Mode | Technique | Why it is justified |
|------|-----------|---------------------|
| `account_and_source` | T1110.001 Brute Force: Password Guessing | Many failures against one account from one source is the typical pattern of password guessing. |
| `source` | T1110 Brute Force | The same source failing against several accounts may be password spraying (T1110.003) or guessing (T1110.001); the log alone cannot tell which, so the parent technique is used. |

The mapping says the pattern is *consistent with* the technique. It is not proof
of an attack.

---

## SOC-002 - Successful login after repeated failures

**Question it answers:** did the guessing work?

**Logic**

1. Group login events by *(source IP, username)* and read each group in time order.
2. Collect failures. When a success appears, count the failures that happened within
   `success_lookback_minutes` before it.
3. If that count is at least `success_min_failures`, raise an alert.
4. A success clears the collected failures, so later successes do not repeat the
   alert and old failures are never counted twice.

Failures and the success must come from the **same account and the same source IP**.

**Severity** (one level higher than SOC-001 for the same count, because a success
means the guesses may have worked)

| Failures before the success | Severity |
|-----------------------------|----------|
| at least the minimum, below the SOC-001 threshold | Medium |
| at least the SOC-001 threshold | High |
| at least 2 x the SOC-001 threshold | Critical |

**Evidence:** the account, source IP, time of the success, number of preceding
failures, time since the first failure, and services and hosts involved. The alert
lists the IDs of the failures and of the success.

**Likely false positives:** a user who mistypes a password a few times and then gets
it right (the sample data includes one on purpose, and it is rated Medium).

**Recommended response (shown in the alert):** treat the account as potentially
compromised until verified: contact the owner, reset the password, revoke sessions
and tokens, review what the account did after the login, and require multi-factor
authentication.

**MITRE ATT&CK**

| Technique | Why it is justified |
|-----------|---------------------|
| T1110 Brute Force | Repeated failures followed by a success match a guessing attempt that may have succeeded. |
| T1078 Valid Accounts | Only if the login is confirmed as unauthorised: the attacker is then using a valid account. The rule cannot confirm this by itself. |

---

## Tuning tips

* Many alerts from legitimate users: raise the threshold or lower the window.
* Missing slow attacks: raise the window (the sample data contains a one-failure-per-20-minutes
  guess that the defaults deliberately do not catch).
* Use `source` grouping when you suspect one source is trying many accounts.
* Alerts are a starting point for an analyst, not a verdict.

## What the rules do not cover

See *Limitations* in the [README](../README.md#limitations).
