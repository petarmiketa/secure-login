## Petar Miketa – Secure Login CLI (Defensive Authentication)

## Theoretical Background

Authentication systems are a fundamental component of modern software applications.  
They are responsible for verifying user identities and protecting accounts from unauthorized access.

Because login endpoints are publicly exposed, they are common targets for brute-force and credential-guessing attacks.  
Without proper defensive controls, attackers can repeatedly attempt authentication until valid credentials are found.

Secure authentication design therefore focuses not only on verifying credentials, but also on limiting abuse and providing visibility into authentication activity.

## Password Storage

Storing plaintext passwords presents a severe risk, as any database compromise would immediately expose all user credentials.  
To mitigate this risk, passwords are stored using cryptographic hashing functions specifically designed for password security.

In this project, bcrypt is used to hash passwords with an automatically generated salt.  
This ensures that identical passwords produce different hashes and significantly increases the cost of brute-force attacks.

## Failed Login Attempts

Repeated failed login attempts are a common indicator of brute-force activity.

While occasional failures can occur during normal usage, a high number of consecutive failures against the same account strongly suggests malicious behavior.  
Tracking these attempts allows the system to react before credentials are compromised.

This project maintains a per-user counter of failed login attempts, stored separately from authentication data.

## Account Lockout Strategy

To limit the effectiveness of brute-force attacks, an account lockout policy is implemented.

The strategy is intentionally simple and rule-based:

- Each failed login attempt increments a counter
- After five consecutive failures, the account is temporarily locked
- The lock remains active for a fixed duration of ten minutes

This approach significantly slows down password guessing attempts while remaining easy to understand and implement.

## Audit Logging

Visibility is a key component of defensive security.

Without logs, it is impossible to detect suspicious behavior or investigate authentication incidents after they occur.  
For this reason, all authentication-related events are recorded in an audit log.

Each log entry includes:
- Timestamp
- Event type (registration or login)
- Username
- Outcome (success, failure, or locked)
- Reason for failure when applicable

This mirrors the type of logging commonly used in real authentication systems.

## Data Storage Design

JSON files are used for storage in this project to keep the implementation transparent and accessible for educational purposes.

While this approach would not be suitable for production environments, it allows clear inspection of:
- Hashed password storage
- Failed attempt counters
- Lockout timestamps

In real-world systems, these components would typically be stored in a secured database.

## Conclusion

This project demonstrates fundamental defensive authentication concepts, including secure password storage, detection of repeated login failures, account lockout mechanisms, and audit logging.

It serves as a practical introduction to how authentication systems defend against brute-force attacks and provides a foundation for more advanced security controls.
