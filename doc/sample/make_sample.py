#!/usr/bin/env python3
"""Generate a synthetic, fully fictional OpenLDAP debug log for the slaplog
sample report.

Nothing here comes from a real directory.  The identities, addresses and data
are reserved for documentation:

  * domain  : dc=example,dc=com            (RFC 2606)
  * IPv4    : 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24  (RFC 5737)

The story the sample tells
--------------------------
Three services run normally.  On 2026-09-16 10:00 a fourth one, "reporting",
starts and becomes the busiest consumer, firing expensive substring and
negated searches that scan the whole directory.  The "top consumer per hour"
bars turn to its colour at that hour and stay there, and the onset marker
lands on 2026-09-16 10:00.

Usage
-----
    python3 make_sample.py > access.log
    # or, from this directory:
    python3 make_sample.py            # writes ./access.log

Then build the report (from the repository root):

    ./slaplog doc/sample/access.log -o html \\
        --title "slaplog sample (synthetic data)" \\
        > doc/sample/slaplog-sample.html
"""

import random
import sys
from datetime import datetime, timezone

random.seed(42)

START = int(datetime(2026, 9, 14, 0, 0, 0, tzinfo=timezone.utc).timestamp())
HOURS = 4 * 24
END = START + HOURS * 3600

THREADS = ["0x7f0000000100", "0x7f0000000200",
           "0x7f0000000300", "0x7f0000000400"]

DOMAIN = "dc=example,dc=com"
PEOPLE = "ou=people," + DOMAIN
GROUPS = "ou=groups," + DOMAIN

# Documentation source addresses, one pool per service.
POOL = ["192.0.2.10", "192.0.2.11", "198.51.100.20",
        "198.51.100.21", "203.0.113.30", "203.0.113.31"]

FILTERS_LIGHT = [
    ("(uid=alice)", 1, 1),
    ("(uid=bob)", 1, 1),
    ("(&(objectClass=person)(uid=carol))", 1, 1),
    ("(mail=*)", 1, 40),
    ("(|(uid=dave)(uid=erin))", 1, 2),
    ("(cn=*smith*)", 1, 0),
]
# The heavy, unindexed family: a substring or a negated filter forces a full
# candidate scan, so the clock runs while almost nothing comes back.
FILTERS_HEAVY = [
    ("(cn=*smith*)", 1, 0),
    ("(&(objectClass=person)(!(uid=*)))", 2, 0),
    ("(employeeNumber=0*)", 2, 0),
    ("(&(employeeType=i)(!(employeeNumber=0*)))", 2, 0),
]

ERRORS = {
    0: "",
    4: "Size limit exceeded",
    10: "Referral",
    32: "No such object",
    49: "Invalid credentials",
    50: "Insufficient access",
    52: "Unavailable",
    53: "Unwilling to perform",
}

seq = 0
conn = 1000
fd = 12
buf = []


def emit(ts, rest, thread=None):
    global seq
    seq += 1
    th = thread or THREADS[seq % len(THREADS)]
    buf.append("%08x.%08x %s %s" % (ts, seq, th, rest))


def accept(ts, c, f, th, src):
    emit(ts, "conn=%d fd=%d ACCEPT from IP=%s:%d (IP=0.0.0.0:389)"
         % (c, f, src, 40000 + c % 20000), th)


def session(ts, dn, ops, src, bind_err=0):
    """One connection: ACCEPT, BIND, the given operations, UNBIND, closed."""
    global conn, fd
    c = conn
    conn += 1
    f = fd
    fd = 12 + (fd - 11) % 1000
    th = THREADS[c % len(THREADS)]

    accept(ts, c, f, th, src)
    o = 0
    emit(ts, 'conn=%d op=%d BIND dn="%s" method=128' % (c, o, dn), th)
    et = random.uniform(0.4, 1.8)
    if bind_err:
        emit(ts, "conn=%d op=%d RESULT tag=97 err=%d qtime=0.000010 etime=%.6f text=%s"
             % (c, o, bind_err, et, ERRORS.get(bind_err, "")), th)
        emit(ts, "conn=%d fd=%d closed" % (c, f), th)
        return
    emit(ts, "conn=%d op=%d RESULT tag=97 err=0 qtime=0.000010 etime=%.6f text="
         % (c, o, et), th)

    for kind, args in ops:
        o += 1
        if kind == "SRCH":
            base, scope, filt, attrs, err, et, nent = args
            emit(ts, 'conn=%d op=%d SRCH base="%s" scope=%d deref=0 filter="%s" attrs="%s"'
                 % (c, o, base, scope, filt, attrs), th)
            emit(ts, "conn=%d op=%d SEARCH RESULT tag=101 err=%d qtime=0.000010 "
                     "etime=%.6f nentries=%d text=%s"
                 % (c, o, err, et, nent, ERRORS.get(err, "")), th)
        elif kind == "CMP":
            d, err, et = args
            emit(ts, "conn=%d op=%d CMP dn=%s" % (c, o, d), th)
            emit(ts, "conn=%d op=%d RESULT tag=111 err=%d qtime=0.000010 etime=%.6f text=%s"
                 % (c, o, err, et, ERRORS.get(err, "")), th)
        else:  # ADD / MOD / DEL / MODRDN
            d, err, et = args
            tag = {"ADD": 105, "MOD": 103, "DEL": 107, "MODRDN": 109}[kind]
            emit(ts, "conn=%d op=%d %s dn=%s" % (c, o, kind, d), th)
            emit(ts, "conn=%d op=%d RESULT tag=%d err=%d qtime=0.000010 etime=%.6f text=%s"
                 % (c, o, tag, err, et, ERRORS.get(err, "")), th)

    o += 1
    emit(ts, "conn=%d op=%d UNBIND" % (c, o), th)
    emit(ts, "conn=%d fd=%d closed" % (c, f), th)


def light_op(filters, base=DOMAIN, err=0, et_lo=1.0, et_hi=6.0):
    filt, scope, default_nent = random.choice(filters)
    if default_nent == 40:
        nent = random.randint(20, 60)
    elif default_nent == 0:
        nent = 0
    else:
        nent = default_nent
    et = random.uniform(et_lo, et_hi)
    attrs = random.choice(["uid,cn,mail", "*", "dn", "uid,cn"])
    return ("SRCH", (base, scope, filt, attrs, err, et, nent))


def heavy_op():
    filt, scope, _ = random.choice(FILTERS_HEAVY)
    et = random.uniform(18.0, 55.0)
    base = random.choice([DOMAIN, DOMAIN, PEOPLE])
    return ("SRCH", (base, scope, filt, "*", 0, et, random.choice([0, 0, 0, 1])))


def main(out):
    emit(START, "slapd starting")

    for hour in range(HOURS):
        hbase = START + hour * 3600
        hod = hour % 24
        night_batch = hod in (2, 3)  # hr-sync runs 02:00-03:59

        # portal: steady, light, every hour.
        for _ in range(6):
            ts = hbase + random.randint(0, 3599)
            session(ts, "uid=portal,ou=services," + DOMAIN,
                    [light_op(FILTERS_LIGHT) for _ in range(random.randint(2, 4))],
                    POOL[0])

        # monitor: a trickle.
        for _ in range(2):
            ts = hbase + random.randint(0, 3599)
            session(ts, "uid=monitor,ou=services," + DOMAIN,
                    [light_op(FILTERS_LIGHT)], POOL[1])

        # legacy-app: light, and some binds fail.
        for _ in range(3):
            ts = hbase + random.randint(0, 3599)
            session(ts, "uid=legacy-app,ou=services," + DOMAIN,
                    [light_op(FILTERS_LIGHT, err=random.choice([0, 0, 32]))],
                    POOL[2], bind_err=49 if random.random() < 0.35 else 0)

        # admin: a few directory changes, morning only.
        if hod in (8, 9) and hour % 2 == 0:
            ts = hbase + random.randint(0, 3599)
            session(ts, "cn=admin," + DOMAIN, [
                ("ADD", ("cn=newuser%d,%s" % (hour, PEOPLE), 0, random.uniform(2, 8))),
                ("MOD", ("cn=alice,%s" % PEOPLE, 0, random.uniform(1, 4))),
                ("CMP", ("cn=bob,%s" % PEOPLE, 0, random.uniform(0.5, 2))),
                ("MODRDN", ("cn=old,%s" % PEOPLE, 0, random.uniform(1, 5))),
                ("DEL", ("cn=stale,%s" % PEOPLE, 0, random.uniform(1, 3))),
            ], POOL[3])

        # hr-sync: the nightly batch, heavy but only two hours a night.
        if night_batch:
            for _ in range(18):
                ts = hbase + random.randint(0, 3599)
                session(ts, "uid=hr-sync,ou=services," + DOMAIN,
                        [heavy_op() for _ in range(2)], POOL[4])

        # reporting: appears on day 3 at 10:00 and takes over.
        if START + hour * 3600 >= int(datetime(2026, 9, 16, 10, 0, 0,
                                               tzinfo=timezone.utc).timestamp()):
            for _ in range(30):
                ts = hbase + random.randint(0, 3599)
                session(ts, "uid=reporting,ou=services," + DOMAIN,
                        [heavy_op() for _ in range(random.randint(1, 3))],
                        POOL[5])

        # One rare server-side failure, so the error donut is not all client.
        if hod == 15 and hour % 24 == 0:
            ts = hbase + random.randint(0, 3599)
            session(ts, "uid=portal,ou=services," + DOMAIN,
                    [light_op(FILTERS_LIGHT, err=52)], POOL[0])

    emit(END - 1, "slapd stopped")

    out.write("\n".join(buf))
    out.write("\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        with open(sys.argv[1], "w", encoding="utf-8") as fh:
            main(fh)
    else:
        main(sys.stdout)
