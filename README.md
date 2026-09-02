# Coralgenz Global - Admin Command Center

Enterprise Administration Portal for User Authentication, Course Google Form Routing, and Salted Hash QR Certificate Issuance.

## 🚀 Features
- 👥 **User Authentication & Course Provisioning**: Create and authorize candidate credentials with instant synchronization to Firebase Authentication (`firebase/auth`) and Cloud Firestore (`users`, `student_users`, `candidates`).
- 🔗 **Course Google Forms Routing**: Manage and sync live Google Forms for Java, Python, C, Frontend Web Engineering, and Full Stack Web Development across `settings/course_forms` and `courses` collection.
- 📜 **Tamper-Proof Certificate & QR Engine**: Generate high-security salted hash QR codes (HMAC-SHA256) for instant verification on `internships.coralgenz.co.in`.
- 🛡️ **Anti-Inspect Security**: Built-in protection against developer tools inspection, raw API key exposure, and unauthorized script modification.

## 🌐 Deployment on Vercel
1. Import this repository into Vercel.
2. Framework Preset: **Other** / **Static Site**.
3. Build Command: *None* (Pure static ESM architecture).
4. Output Directory: `.` (Root directory).
5. Click **Deploy**.

---
© 2026 Coralgenz Global. All Rights Reserved.
