"""
Sample log data for testing the forensic framework.
"""

SAMPLE_AUTH_LOGS = [
    "Jan 15 10:30:15 webserver sshd[1234]: Failed password for root from 203.0.113.50 port 22 ssh2",
    "Jan 15 10:30:18 webserver sshd[1234]: Failed password for root from 203.0.113.50 port 22 ssh2",
    "Jan 15 10:30:21 webserver sshd[1234]: Failed password for root from 203.0.113.50 port 22 ssh2",
    "Jan 15 10:30:25 webserver sshd[1235]: Accepted password for admin from 203.0.113.50 port 22 ssh2",
    "Jan 15 10:30:26 webserver sshd[1235]: pam_unix(sshd:session): session opened for user admin by (uid=0)",
    "Jan 15 10:31:00 webserver sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
    "Jan 15 10:31:05 webserver sudo: pam_unix(sudo:session): session opened for user root by admin(uid=1000)",
    "Jan 15 10:32:15 webserver sshd[1236]: Accepted publickey for deployer from 10.0.0.5 port 54321 ssh2",
    "Jan 15 10:35:00 webserver kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.50 DST=10.0.0.1 LEN=60 TOS=0x00 PROTO=TCP SPT=45678 DPT=3306",
    "Jan 15 10:35:05 webserver mysql[5678]: Access denied for user 'root'@'203.0.113.50' (using password: YES)",
    "Jan 15 10:40:00 dbserver sshd[2345]: Failed password for invalid user hacker from 203.0.113.50 port 22 ssh2",
    "Jan 15 10:40:10 dbserver sshd[2345]: Disconnecting invalid user hacker 203.0.113.50 port 22: Too many authentication failures",
    "Jan 15 14:00:00 webserver sshd[3456]: Accepted publickey for admin from 192.168.1.100 port 12345 ssh2",
    "Jan 15 14:00:01 webserver sshd[3456]: pam_unix(sshd:session): session opened for user admin",
]

SAMPLE_SYSLOG = [
    "Jan 15 10:00:00 webserver systemd[1]: Starting Apache HTTP Server...",
    "Jan 15 10:00:01 webserver systemd[1]: Started Apache HTTP Server.",
    "Jan 15 10:00:05 webserver apache2[1000]: AH00558: apache2: Could not reliably determine the server's fully qualified domain name",
    "Jan 15 10:15:00 webserver cron[1100]: (root) CMD (/usr/bin/logrotate /etc/logrotate.conf)",
    "Jan 15 10:30:00 webserver kernel: [1234.567890] Out of memory: Kill process 9999 (java) score 900 or sacrifice child",
    "Jan 15 10:35:00 webserver systemd[1]: nginx.service: Main process exited, code=killed, status=9/KILL",
    "Jan 15 10:35:01 webserver systemd[1]: nginx.service: Failed with result 'signal'.",
]

SAMPLE_APPLICATION_LOGS = [
    '2024-01-15T10:30:00.000Z INFO [main] Application started successfully',
    '2024-01-15T10:30:05.123Z DEBUG [worker-1] Processing request: GET /api/users',
    '2024-01-15T10:30:05.456Z INFO [worker-1] User authenticated: id=12345, ip=192.168.1.50',
    '2024-01-15T10:30:10.789Z WARNING [worker-2] Rate limit exceeded for ip=203.0.113.50',
    '2024-01-15T10:30:15.000Z ERROR [worker-1] Database connection timeout after 30s',
    '2024-01-15T10:30:16.000Z ERROR [worker-1] Failed to execute query: SELECT * FROM users WHERE id = 12345',
    '2024-01-15T10:30:20.000Z CRITICAL [main] Unhandled exception in request handler: NullPointerException',
    '2024-01-15T10:35:00.000Z INFO [worker-3] Suspicious activity detected: multiple failed auth from 203.0.113.50',
    '2024-01-15T10:40:00.000Z INFO [security] Blocking IP 203.0.113.50 due to brute force attempt',
]


def get_all_sample_logs() -> list[str]:
    """Get all sample logs combined."""
    return SAMPLE_AUTH_LOGS + SAMPLE_SYSLOG + SAMPLE_APPLICATION_LOGS
