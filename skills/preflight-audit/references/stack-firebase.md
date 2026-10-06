# Firebase

Load this when the scan reports `stacks` with `firebase` or any `data-firebase-*` rule.

Firebase client SDKs talk straight to Firestore, the Realtime Database (RTDB) and Cloud Storage from the browser or app. Security Rules are the only gate. Two key facts decide every finding:

- The web `firebaseConfig` (`apiKey`, `authDomain`, `projectId`, `appId`) is public by design and is not a secret. Never report it as a leak. Keep it restricted to Firebase APIs and never enable the Gemini / Generative Language API on a key that ships to clients.
- A service account JSON (`"type": "service_account"` with a `private_key`) is a secret with full admin rights. The Admin SDK and server client libraries bypass all rules, so rules findings do not apply to backend code that uses them; the control there is IAM.

Rules files: `firestore.rules`, `storage.rules`, `database.rules.json` (paths are set in `firebase.json`). Deploy changes with `firebase deploy --only firestore:rules,storage,database` and test them in the emulator first.

## Owner-only rules

Scope every per-user document to its owner. Never ship `if true`, `allow read, write;` (no condition means always) or bare `request.auth != null` for per-user data.

```
// firestore.rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    match /posts/{postId} {
      allow read: if true;   // only if posts are public by design
      allow create: if request.auth != null
                    && request.resource.data.authorUid == request.auth.uid;
      allow update: if request.auth != null
                    && resource.data.authorUid == request.auth.uid
                    && request.resource.data.authorUid == resource.data.authorUid;  // no change of ownership
      allow delete: if request.auth != null
                    && resource.data.authorUid == request.auth.uid;
    }
  }
}
```

```
// storage.rules
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{userId}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

`match /{document=**}` and `match /{allPaths=**}` at the top cover every document or file. An open rule there exposes everything, including uploaded ID photos and selfies, which cannot be un-leaked. Rules are additive: one open rule wins over every strict rule for the same path.

False-positive notes: `allow read: if true` on a collection that is public by design (leaderboard, published content) is fine when writes are restricted and the documents hold no personal data; the scanner only reports open reads on paths that look private. `allow create: if true` for a public form collection is acceptable only with field validation (`request.resource.data.keys().hasOnly([...])` and type and size checks).

## Test-mode rules

The console's "test mode" writes a date check that opens everything until the date:

```
allow read, write: if request.time < timestamp.date(2026, 11, 4);
```

RTDB test mode is `".read": "now < 1767225600000"`. Until the date anyone with the project id can read, change or delete all data; after it, the app breaks. Replace it with owner-only rules before launch. There is no safe production use.

## Any signed-in user

`allow read, write: if request.auth != null;` looks secure, but anyone can create an account (or sign in anonymously if that provider is on) and then read or change every other user's documents. It is the most common "looks fine" Firebase bug. Helpers hide it too:

```
function isSignedIn() { return request.auth != null; }
match /posts/{postId} { allow write: if isSignedIn(); }   // any user can edit any post
```

An OR is as open as its most open branch: `isAdmin() || isSignedIn()` lets every signed-in user in. Compare the user to the document instead: `request.auth.uid == userId` for paths keyed by uid, `resource.data.ownerUid == request.auth.uid` for existing documents, `request.resource.data.ownerUid == request.auth.uid` on create, and on update both `resource.data.ownerUid` and `request.resource.data.ownerUid` so ownership cannot be changed.

False-positive note: data that is genuinely shared by every signed-in user (a team workspace where all members are trusted) can use `request.auth != null`; judge by whether the collection holds per-user private data. Create-only rules and reads of non-private paths are not reported.

## Roles with custom claims

A role stored on `users/{uid}` that the user may write is a privilege escalation: the user edits their own document and sets `role: 'admin'`. Put roles in custom claims, set only from the server:

```js
// server, Admin SDK
await admin.auth().setCustomUserClaims(uid, { admin: true })
```

```
allow write: if request.auth.token.admin == true;
```

A bootstrap admin recognised by `request.auth.token.email == '<owner address>'` is only as strong as email verification: add `&& request.auth.token.email_verified == true`, or better, replace it with the claim above.

If a role field must live in the document, block clients from touching it:

```
match /users/{userId} {
  allow read: if request.auth.uid == userId;
  allow update: if request.auth.uid == userId
    && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'plan', 'credits']);
}
```

Claims reach the client on the next ID token refresh (`getIdToken(true)`), so the app may need to refresh after a change.

False-positive note: fine when the write rule blocks the field (as above) or only the Admin SDK writes the document.

## Realtime Database rules

RTDB rules cascade down: a `.read` or `.write` granted on a parent cannot be taken back by a child.

```json
{
  "rules": {
    ".read": false,
    ".write": false,
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}
```

`".read": true` or `".write": true` at the root opens the whole database. `"auth != null"` lets any signed-in user in. Use `.validate` for field types and sizes.

False-positive note: a `.read: true` on a public node (leaderboard, public config) with `.write` locked is fine.

## Prove it on your own project

This skill sends no requests: give the user these commands, or hand the check to the live-exposure-check skill. With their own project id, logged out, these must answer `PERMISSION_DENIED`, 401 or 403, never data:

```
curl -s "https://firestore.googleapis.com/v1/projects/<your-project-id>/databases/(default)/documents/users"
curl -s "<databaseURL from firebaseConfig>/users.json"   # https://<project-id>-default-rtdb.firebaseio.com (us-central1) or https://<project-id>-default-rtdb.<region>.firebasedatabase.app
curl -s "https://firebasestorage.googleapis.com/v0/b/<your-bucket>/o"
```

Use the `databaseURL` from the app's `firebaseConfig`; an error page from the wrong host proves nothing.

Then sign in as test user B and confirm B cannot read user A's document path. The rules playground in the console and the emulator test suite (`@firebase/rules-unit-testing`) can run the same checks before every deploy.

LAST-VERIFIED: 2026-10-06
