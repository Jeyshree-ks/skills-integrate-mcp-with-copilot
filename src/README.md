# Mergington High School Activities API

A simple FastAPI application where students can browse activities and teachers manage registrations.

## Features

- View all available extracurricular activities
- Public participant lists
- Teacher login, logout, and teacher-only signup/unregister

## Getting Started

1. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. From the repository root, assign a teacher username and password:

   ```
   python -m src.auth teacher-name
   ```

   Enter and confirm an assigned password of at least 12 characters when prompted.
   Repeat for additional teachers or to reset a password. There are no default accounts.
   The command stores salted PBKDF2-SHA256 password hashes in `src/teachers.json`.
   This backend-only file is ignored by Git; never commit it or share assigned passwords.
   A missing file produces an explicit login configuration error.

3. Run the application from the repository root:

   ```
   uvicorn src.app:app --reload
   ```

4. Open http://localhost:8000. Use the user icon at the top right, select
   **Teacher login**, and enter the assigned credentials. Logged-in teachers can
   register and unregister students. Students can still browse all participant lists.

   API documentation:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login` | Exchange a JSON username/password for an eight-hour bearer token |
| POST   | `/auth/logout` | Revoke the current teacher token |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Register a student (teacher token required) |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister a student (teacher token required) |

Protected endpoints require `Authorization: Bearer <access_token>`. The browser
keeps this token only in memory, so reloading the page requires logging in again.
Expired or invalid tokens return HTTP 401 and restore student view.
Sessions are in memory: restarting the server logs everyone out. Run a single
application worker; multiple workers require a shared session store.
After resetting a teacher password, restart the server to revoke existing sessions.
Use HTTPS outside local development to protect passwords and tokens in transit.
No account-management page is provided; credentials are assigned through the CLI.

## Tests

From the repository root:

```
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
