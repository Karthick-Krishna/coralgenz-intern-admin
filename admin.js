/**
 * Coralgenz Global - Admin Command Center Controller
 * User Authentication, Course Google Form Routing & Certificate QR Engine
 * ======================================================================
 */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { 
  getFirestore, 
  collection, 
  doc, 
  setDoc, 
  deleteDoc, 
  getDoc,
  getDocs,
  query,
  where,
  onSnapshot, 
  serverTimestamp 
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";

import { 
  getAuth, 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  updateProfile 
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

import { 
  generateSaltedHashToken, 
  verifyAndDecodeSaltedHash, 
  isSaltedHashToken 
} from "./crypto-salt.js";

// ==========================================
// 1. ENCRYPTED CLOUD GATEWAY CONFIGURATION
// ==========================================
const _cgzVaultInit = (() => {
  const _vk = "CGZ_VAULT_2026";
  const _vp = "OGU7Lz8KMDV2ZRBxe0wiFCMbYSMQAhc1a2lrUXA/GWgaGzgHLitHe2d3G38iOQ83IRl2cxBRR0IrAzUyNyg7bm59UV9AVy8gPzEsbDwiIDpAXkFeKjcpcTAoJyk2PkFVU0YzaTkwO2N5biQtXVpXVTcOPn1sYzYjJj5eV1dYOWozMSIkJyInN1tAQRRvZSkrOTM0KzEdR1NZUzdlYH01LictODhXXkgbKikuOiQvJiQ9L0EeVF8xIjg+JSQmODstU1dXGCI3Kn16YzgpJyxTV1tYJBQ/MTIkJwUwfQgSAwZ1d2huZHJseGBrABIeFCI3KhYyY29uZWUDAAQGcXZobG91YXhmZUVVUAx7Jjs6ZHIwfmRnA1NUUCFwYzwzdmZ/dnMQXVdXMDIoOjskOzgdOxAKEHFud2NtFQ1gBANvaBJP";
  const _raw = atob(_vp);
  let _buf = "";
  for (let i = 0; i < _raw.length; i++) {
    _buf += String.fromCharCode(_raw.charCodeAt(i) ^ _vk.charCodeAt(i % _vk.length));
  }
  return JSON.parse(_buf);
})();

// Initialize Firebase App, Firestore Database & Auth Services
const app = initializeApp(_cgzVaultInit);
const db = getFirestore(app);
const adminAuth = getAuth(app);

// Secondary Auth Worker for Provisioning Candidate Accounts (avoids session conflicts)
const authWorkerApp = initializeApp(_cgzVaultInit, "CoralgenzAuthWorker");
const authWorker = getAuth(authWorkerApp);

// Root Administrator Policy: Strictly Restricted to karthick@coralgenz.co.in
const AUTHORIZED_ADMIN_EMAIL = "karthick@coralgenz.co.in";

// Global State
let currentStudentList = [];
let currentCertsList = [];
let qrCodeInstance = null;
let currentSaltedToken = "";

// Course Google Forms Default Embed Mapping
const DEFAULT_COURSE_FORMS = {
  java: "https://docs.google.com/forms/d/e/1FAIpQLSd1-Dummy-Java-Assessment-Coralgenz2026/viewform",
  python: "https://docs.google.com/forms/d/e/1FAIpQLSd2-Dummy-Python-Assessment-Coralgenz2026/viewform",
  c: "https://docs.google.com/forms/d/e/1FAIpQLSd3-Dummy-C-Programming-Assessment-Coralgenz2026/viewform",
  webdev: "https://docs.google.com/forms/d/e/1FAIpQLSd4-Dummy-WebDev-Assessment-Coralgenz2026/viewform",
  "web development": "https://docs.google.com/forms/d/e/1FAIpQLSd4-Dummy-WebDev-Assessment-Coralgenz2026/viewform",
  fullstack: "https://docs.google.com/forms/d/e/1FAIpQLSd5-Dummy-Fullstack-Assessment-Coralgenz2026/viewform"
};

let activeFormsMap = { ...DEFAULT_COURSE_FORMS };

// ==========================================
// 1B. ADMIN AUTHENTICATION GATEWAY CONTROLLER
// ==========================================
const adminAuthGate = document.getElementById("admin-auth-gate");
const adminLoginForm = document.getElementById("admin-login-form");
const adminAuthEmail = document.getElementById("admin-auth-email");
const adminAuthPassword = document.getElementById("admin-auth-password");
const adminLoginStatusAlert = document.getElementById("admin-login-status-alert");
const btnAdminLoginSubmit = document.getElementById("btn-admin-login-submit");
const btnAdminLogout = document.getElementById("btn-admin-logout");

function showAdminLoginAlert(type, msg) {
  if (!adminLoginStatusAlert) return;
  adminLoginStatusAlert.className = `admin-status-box status-${type}`;
  adminLoginStatusAlert.innerHTML = `<div>${msg}</div>`;
  adminLoginStatusAlert.style.display = "block";
}

async function handleAdminLogin(e) {
  if (e) e.preventDefault();

  const inputEmail = (adminAuthEmail?.value || "").trim().toLowerCase();
  const inputPassword = (adminAuthPassword?.value || "").trim();

  if (!inputEmail || !inputPassword) {
    showAdminLoginAlert("error", "Please enter both Administrator Email and Password.");
    return;
  }

  // Strict Policy Check: Only karthick@coralgenz.co.in permitted
  if (inputEmail !== AUTHORIZED_ADMIN_EMAIL.toLowerCase()) {
    showAdminLoginAlert("error", `⛔ <strong>Access Denied!</strong><br>The email <code>${inputEmail}</code> is not authorized.<br>Only root administrator (<code>${AUTHORIZED_ADMIN_EMAIL}</code>) is permitted to access this Command Center.`);
    return;
  }

  if (inputPassword.length < 6) {
    showAdminLoginAlert("error", "Password must be at least 6 characters long.");
    return;
  }

  if (btnAdminLoginSubmit) {
    btnAdminLoginSubmit.disabled = true;
    btnAdminLoginSubmit.innerHTML = `<span>Verifying Admin Credentials... ⏳</span>`;
  }

  try {
    let authUser = null;

    // 1. Attempt Sign In via Firebase Auth
    try {
      const userCred = await signInWithEmailAndPassword(adminAuth, inputEmail, inputPassword);
      authUser = userCred.user;
    } catch (authErr) {
      // If administrator account does not yet exist in Firebase Auth, automatically provision/create it with the provided password
      if (authErr.code === "auth/user-not-found" || authErr.code === "auth/invalid-credential" || authErr.code === "auth/invalid-email") {
        try {
          const createCred = await createUserWithEmailAndPassword(adminAuth, inputEmail, inputPassword);
          authUser = createCred.user;
          try {
            await updateProfile(authUser, { displayName: "Coralgenz Administrator" });
          } catch(pErr) {}
        } catch (createErr) {
          throw authErr;
        }
      } else {
        throw authErr;
      }
    }

    // Store verified session
    sessionStorage.setItem("cgz_admin_session", inputEmail);

    if (adminAuthGate) {
      adminAuthGate.style.display = "none";
    }

    showToast(`👑 Welcome back, Administrator (${inputEmail})!`);
  } catch (err) {
    console.error("Admin Login Error:", err);
    let errMsg = "Invalid administrator password. Please check your credentials.";
    if (err.code === "auth/wrong-password" || err.code === "auth/invalid-credential") {
      errMsg = "Incorrect administrator password. Please try again.";
    } else if (err.message) {
      errMsg = err.message;
    }
    showAdminLoginAlert("error", `❌ <strong>Authentication Failed:</strong> ${errMsg}`);
  } finally {
    if (btnAdminLoginSubmit) {
      btnAdminLoginSubmit.disabled = false;
      btnAdminLoginSubmit.innerHTML = `<span>🔐 Authenticate & Enter Dashboard</span>`;
    }
  }
}

async function handleAdminLogout() {
  if (!confirm("Are you sure you want to sign out of the Admin Command Center?")) return;

  try {
    await signOut(adminAuth);
  } catch (e) {}

  sessionStorage.removeItem("cgz_admin_session");

  if (adminAuthPassword) adminAuthPassword.value = "";
  if (adminLoginStatusAlert) adminLoginStatusAlert.style.display = "none";
  if (adminAuthGate) adminAuthGate.style.display = "flex";

  showToast("🚪 Signed out of Admin Command Center.");
}

function checkAdminAuthSession() {
  const sessionUser = sessionStorage.getItem("cgz_admin_session");
  if (sessionUser && sessionUser.toLowerCase() === AUTHORIZED_ADMIN_EMAIL.toLowerCase()) {
    if (adminAuthGate) adminAuthGate.style.display = "none";
  } else {
    if (adminAuthGate) adminAuthGate.style.display = "flex";
  }

  onAuthStateChanged(adminAuth, (user) => {
    if (user && user.email && user.email.toLowerCase() === AUTHORIZED_ADMIN_EMAIL.toLowerCase()) {
      sessionStorage.setItem("cgz_admin_session", user.email);
      if (adminAuthGate) adminAuthGate.style.display = "none";
    }
  });
}

if (adminLoginForm) {
  adminLoginForm.addEventListener("submit", handleAdminLogin);
}

if (btnAdminLogout) {
  btnAdminLogout.addEventListener("click", handleAdminLogout);
}

// ==========================================
// 2. DOM ELEMENTS - AUTH & USERS
// ==========================================
const studentAuthForm = document.getElementById("add-student-auth-form");
const studentNameInput = document.getElementById("student-name-input");
const studentEmailInput = document.getElementById("student-email-input");
const studentPwdInput = document.getElementById("student-password-input");
const studentCourseSelect = document.getElementById("student-course-select");
const studentStatusSelect = document.getElementById("student-access-status");
const studentBatchInput = document.getElementById("student-batch-input");
const btnSaveStudent = document.getElementById("btn-save-student-user");
const btnGenStrongPwd = document.getElementById("btn-gen-strong-pwd");
const btnQuickSampleStudent = document.getElementById("btn-quick-sample-student");
const btnResetStudentForm = document.getElementById("btn-reset-student-form");
const studentStatusAlert = document.getElementById("student-form-status-alert");
const btnCopyStudentCreds = document.getElementById("btn-copy-student-creds");
const btnTriggerSaveUser = document.getElementById("btn-trigger-save-user");

// Preview Elements
const prevCredName = document.getElementById("prev-cred-name");
const prevCredEmail = document.getElementById("prev-cred-email");
const prevCredPwd = document.getElementById("prev-cred-pwd");
const prevCredCourse = document.getElementById("prev-cred-course");
const prevCredStatus = document.getElementById("prev-cred-status");
const prevCredForm = document.getElementById("prev-cred-form");

// Metrics & Tables
const metricTotalStudents = document.getElementById("metric-total-students");
const metricActiveStudents = document.getElementById("metric-active-students");
const tabStudentCount = document.getElementById("tab-student-count");
const studentTableSearch = document.getElementById("student-table-search");
const studentTableBody = document.getElementById("student-users-table-body");
const toastContainer = document.getElementById("admin-toast");

// ==========================================
// 3. DOM ELEMENTS - COURSE FORMS CONFIG
// ==========================================
const formUrlJava = document.getElementById("form-url-java");
const formUrlPython = document.getElementById("form-url-python");
const formUrlC = document.getElementById("form-url-c");
const formUrlWebdev = document.getElementById("form-url-webdev");
const formUrlFullstack = document.getElementById("form-url-fullstack");
const courseFormsConfigForm = document.getElementById("course-forms-config-form");
const btnSaveCourseForms = document.getElementById("btn-save-course-forms");
const btnLoadDefaultForms = document.getElementById("btn-load-default-forms");
const formsConfigStatusAlert = document.getElementById("forms-config-status-alert");

// ==========================================
// 4. DOM ELEMENTS - CERTIFICATE GENERATOR
// ==========================================
const certForm = document.getElementById("candidate-cert-form");
const candNameInput = document.getElementById("cand-name");
const candEmailInput = document.getElementById("cand-email");
const candTrackInput = document.getElementById("cand-track");
const candSerialInput = document.getElementById("cand-serial");
const candIssueDateInput = document.getElementById("cand-issue-date");
const candVerifyUrlInput = document.getElementById("cand-verify-url");
const btnSaveFirebase = document.getElementById("btn-save-firebase");
const btnGenNewId = document.getElementById("btn-gen-new-id");
const btnQuickSample = document.getElementById("btn-quick-sample");
const btnResetForm = document.getElementById("btn-reset-form");
const btnPreviewCert = document.getElementById("btn-preview-cert");
const certStatusAlert = document.getElementById("form-status-alert");

const prevName = document.getElementById("prev-candidate-name");
const prevEmail = document.getElementById("prev-candidate-email");
const prevTrack = document.getElementById("prev-track-name");
const prevCertId = document.getElementById("prev-cert-id");
const prevIssueDate = document.getElementById("prev-issue-date");
const qrCanvasBox = document.getElementById("qr-code-canvas-box");
const btnDownloadQrImg = document.getElementById("btn-download-qr-img");
const btnPrintAdminCert = document.getElementById("btn-print-admin-cert");
const btnCopyPublicLink = document.getElementById("btn-copy-public-link");
const metricTotalCerts = document.getElementById("metric-total-certs");
const tabCertCount = document.getElementById("tab-cert-count");
const certTableSearchInput = document.getElementById("table-search-input");
const certTableBody = document.getElementById("certificates-table-body");

// ==========================================
// 5. TOAST NOTIFICATION HELPER
// ==========================================
function showToast(msg) {
  if (!toastContainer) return;
  const toast = document.createElement("div");
  toast.className = "admin-toast";
  toast.innerHTML = `<span>${msg}</span>`;
  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// ==========================================
// 6. TAB NAVIGATION CONTROLLER
// ==========================================
function initTabNavigation() {
  const tabButtons = document.querySelectorAll(".admin-tab-btn");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTabId = btn.getAttribute("data-tab");
      if (window.switchAdminTab) {
        window.switchAdminTab(targetTabId);
      }
    });
  });
}

// ==========================================
// 7. USER AUTH & COURSE ACCESS MANAGEMENT
// ==========================================
function showStudentAlert(type, msg) {
  if (!studentStatusAlert) return;
  studentStatusAlert.className = `admin-status-box status-${type}`;
  studentStatusAlert.innerHTML = `<div>${msg}</div>`;
  studentStatusAlert.style.display = "block";
}

function generateStrongPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%&*";
  let pwd = "CG@";
  for (let i = 0; i < 7; i++) {
    pwd += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  if (studentPwdInput) studentPwdInput.value = pwd;
  updateStudentPreview();
  return pwd;
}

function getCourseFormUrl(course) {
  const c = (course || "").toLowerCase().trim();
  if (c.includes("java")) return activeFormsMap.java || DEFAULT_COURSE_FORMS.java;
  if (c.includes("python")) return activeFormsMap.python || DEFAULT_COURSE_FORMS.python;
  if (c === "c" || c.includes("c programming")) return activeFormsMap.c || DEFAULT_COURSE_FORMS.c;
  if (c.includes("web")) return activeFormsMap.webdev || DEFAULT_COURSE_FORMS.webdev;
  return activeFormsMap.fullstack || DEFAULT_COURSE_FORMS.fullstack;
}

function updateStudentPreview() {
  const name = studentNameInput?.value.trim() || "—";
  const email = studentEmailInput?.value.trim() || "—";
  const pwd = studentPwdInput?.value.trim() || "—";
  const course = studentCourseSelect?.value || "Fullstack";
  const status = studentStatusSelect?.value || "active";

  if (prevCredName) prevCredName.textContent = name;
  if (prevCredEmail) prevCredEmail.textContent = email;
  if (prevCredPwd) prevCredPwd.textContent = pwd;
  if (prevCredCourse) prevCredCourse.textContent = `⚡ ${course}`;
  
  const formUrl = getCourseFormUrl(course);
  if (prevCredForm) {
    prevCredForm.textContent = formUrl.length > 35 ? `${formUrl.substring(0, 32)}...` : formUrl;
    prevCredForm.title = formUrl;
  }

  if (prevCredStatus) {
    if (status === "active") {
      prevCredStatus.textContent = "🟢 Access Granted";
      prevCredStatus.style.background = "rgba(34, 197, 94, 0.15)";
      prevCredStatus.style.color = "#4ade80";
    } else {
      prevCredStatus.textContent = "🔴 Access Suspended";
      prevCredStatus.style.background = "rgba(239, 68, 68, 0.15)";
      prevCredStatus.style.color = "#f87171";
    }
  }
}

// Real-time input listeners
[studentNameInput, studentEmailInput, studentPwdInput, studentCourseSelect, studentStatusSelect, studentBatchInput].forEach(elem => {
  if (elem) {
    elem.addEventListener("input", updateStudentPreview);
    elem.addEventListener("change", updateStudentPreview);
  }
});

// Save User to Firebase Authentication & Firestore
async function saveStudentUserToFirebase(e) {
  if (e) e.preventDefault();

  const name = studentNameInput?.value.trim();
  const email = studentEmailInput?.value.trim().toLowerCase();
  const password = studentPwdInput?.value.trim();
  const course = studentCourseSelect?.value || "Fullstack";
  const status = studentStatusSelect?.value || "active";
  const batch = studentBatchInput?.value.trim() || "Cohort 2026";

  if (!name || !email || !password || !course) {
    showStudentAlert("error", "Please fill in User Name, Email, Password, and Course.");
    return;
  }

  if (password.length < 6) {
    showStudentAlert("error", "Password must be at least 6 characters long for Firebase Authentication.");
    return;
  }

  const assignedFormUrl = getCourseFormUrl(course);
  const docKey = email.replace(/[^a-zA-Z0-9]/g, "_");

  if (btnSaveStudent) {
    btnSaveStudent.disabled = true;
    btnSaveStudent.innerHTML = `<span>Registering in Firebase Auth... ⏳</span>`;
  }

  let authUid = null;
  let authStatusMsg = "Created in Firebase Auth";

  try {
    // 1. Create User in Firebase Authentication (Auth Service)
    try {
      const userCredential = await createUserWithEmailAndPassword(authWorker, email, password);
      if (userCredential && userCredential.user) {
        authUid = userCredential.user.uid;
        try {
          await updateProfile(userCredential.user, { displayName: name });
        } catch (profileErr) {
          console.warn("Could not update auth profile displayName:", profileErr);
        }
      }
    } catch (authErr) {
      if (authErr.code === "auth/email-already-in-use") {
        authStatusMsg = "Existing user in Firebase Auth (Credentials & Course Updated)";
      } else {
        console.warn("Firebase Auth Notice:", authErr);
        authStatusMsg = `Auth: ${authErr.message || authErr.code}`;
      }
    }

    // 2. Prepare Firestore Database Record
    const userData = {
      uid: authUid || docKey,
      name: name,
      candidateName: name,
      displayName: name,
      email: email,
      password: password,
      course: course,
      track: course,
      status: status,
      accessStatus: status,
      access: status === "active" ? "granted" : "suspended",
      accessGranted: status === "active",
      formUrl: assignedFormUrl,
      googleFormUrl: assignedFormUrl,
      batch: batch,
      updatedAt: serverTimestamp(),
      createdAt: serverTimestamp()
    };

    // 3. Save to Firestore (users, student_users, and candidates collections)
    await setDoc(doc(db, "users", docKey), userData, { merge: true });
    await setDoc(doc(db, "student_users", docKey), userData, { merge: true });
    
    if (authUid && authUid !== docKey) {
      await setDoc(doc(db, "users", authUid), userData, { merge: true });
      await setDoc(doc(db, "student_users", authUid), userData, { merge: true });
    }

    // 4. Save to candidates collection in exact Firebase schema
    const courseCode = course.toLowerCase().includes("java") ? "java" :
                       course.toLowerCase().includes("python") ? "python" :
                       (course.toLowerCase() === "c" || course.toLowerCase().includes("c ")) ? "c" :
                       course.toLowerCase().includes("web") ? "web" : "fullstack";

    const courseTitle = courseCode === "java" ? "Java Developer" :
                        courseCode === "python" ? "Python Developer" :
                        courseCode === "c" ? "C Programming & Systems" :
                        courseCode === "web" ? "Frontend Web Engineering" :
                        "Full Stack Web Development";

    const candidateDoc = {
      name: name,
      email: email,
      course: courseCode,
      courseTitle: courseTitle,
      status: status === "active" ? "approved" : "suspended",
      customFormUrl: "",
      offerId: `CG-2026-${courseCode.toUpperCase()}-${Math.floor(1000 + Math.random() * 9000)}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await setDoc(doc(db, "candidates", email), candidateDoc, { merge: true });
    if (docKey !== email) {
      await setDoc(doc(db, "candidates", docKey), candidateDoc, { merge: true });
    }

    showStudentAlert("success", `✅ <strong>User Authenticated & Access Granted!</strong><br>👤 User: <strong>${name}</strong> (${email})<br>🔑 Password: <code>${password}</code><br>📘 Course: <strong>${course}</strong><br>⚡ Firebase Auth: <strong>${authStatusMsg}</strong><br>🔗 Target Form: <span style="font-size:0.75rem; word-break:break-all;">${assignedFormUrl}</span>`);
    showToast(`🎉 User ${name} authenticated in Firebase with ${course} access!`);
  } catch (err) {
    console.error("Firestore user write error:", err);
    showStudentAlert("error", `Firebase Write Error: ${err.message}. Please verify Firestore database rules.`);
    showToast("⚠️ Firebase write error.");
  } finally {
    if (btnSaveStudent) {
      btnSaveStudent.disabled = false;
      btnSaveStudent.innerHTML = `<span>🚀 Save User to Firebase & Grant Access</span><span>💾</span>`;
    }
  }
}

if (studentAuthForm) {
  studentAuthForm.addEventListener("submit", saveStudentUserToFirebase);
}

if (btnTriggerSaveUser) {
  btnTriggerSaveUser.addEventListener("click", saveStudentUserToFirebase);
}

// Real-time Firestore Listener for Users
function listenToFirebaseUsers() {
  try {
    const usersCol = collection(db, "users");

    onSnapshot(usersCol, (snapshot) => {
      currentStudentList = [];
      snapshot.forEach(docSnap => {
        currentStudentList.push({ id: docSnap.id, ...docSnap.data() });
      });

      if (metricTotalStudents) metricTotalStudents.textContent = currentStudentList.length;
      if (tabStudentCount) tabStudentCount.textContent = currentStudentList.length;

      const activeCount = currentStudentList.filter(s => (s.status || s.accessStatus || "active") === "active").length;
      if (metricActiveStudents) metricActiveStudents.textContent = activeCount;

      renderUsersTable(currentStudentList);
    }, (error) => {
      console.warn("Firestore users listener snapshot note:", error);
      renderUsersTable([]);
    });
  } catch (err) {
    console.error("Firestore user listener initialization:", err);
    renderUsersTable([]);
  }
}

function getCourseBadgeClass(course) {
  const c = (course || "").toLowerCase();
  if (c.includes("java")) return "badge-course badge-course-java";
  if (c.includes("python")) return "badge-course badge-course-python";
  if (c.includes("c") && !c.includes("java") && !c.includes("stack")) return "badge-course badge-course-c";
  if (c.includes("web")) return "badge-course badge-course-web";
  return "badge-course badge-course-fullstack";
}

function renderUsersTable(users) {
  if (!studentTableBody) return;

  if (users.length === 0) {
    studentTableBody.innerHTML = `
      <tr>
        <td colspan="5" class="td-empty" style="text-align: center; padding: 2rem 1rem; color: #94a3b8;">
          No authenticated users found in Firebase Firestore.<br>Fill the form above and click <strong>"Save User to Firebase & Grant Access"</strong> to add your first user.
        </td>
      </tr>
    `;
    return;
  }

  studentTableBody.innerHTML = users.map(u => {
    const name = u.name || u.candidateName || "User";
    const email = u.email || "—";
    const password = u.password || "••••••••";
    const course = u.course || u.track || "Fullstack";
    const status = (u.status || u.accessStatus || "active").toLowerCase();
    const isAccessActive = status === "active" || status === "granted";
    const docKey = email.replace(/[^a-zA-Z0-9]/g, "_");

    return `
      <tr data-user-email="${email}">
        <td>
          <div class="td-candidate-info">
            <span class="td-cand-name">${name}</span>
            <span class="td-cand-email">${email}</span>
          </div>
        </td>
        <td>
          <span class="${getCourseBadgeClass(course)}">${course}</span>
        </td>
        <td>
          <div class="pwd-masked-box">
            <span class="pwd-text font-mono" id="pwd-display-${docKey}">••••••••</span>
            <button class="btn-text-action" title="Toggle Show/Hide Password" onclick="window.adminAppTogglePwdVisibility('${docKey}', '${password}')">👁️</button>
          </div>
        </td>
        <td>
          <span class="${isAccessActive ? 'badge-status-active' : 'badge-status-suspended'}">
            ${isAccessActive ? '🟢 Granted' : '🔴 Suspended'}
          </span>
        </td>
        <td>
          <div class="table-action-btns">
            <button class="btn-tbl-action btn-tbl-copy" title="Copy User Credentials" onclick="window.adminAppCopyStudentCreds('${email}')">
              📋 Copy
            </button>
            <button class="btn-toggle-status ${isAccessActive ? 'btn-status-revoke' : 'btn-status-grant'}" title="Toggle Access" onclick="window.adminAppToggleStudentAccess('${email}', '${isAccessActive ? 'suspended' : 'active'}')">
              ${isAccessActive ? '🔒 Revoke' : '🔓 Grant'}
            </button>
            <button class="btn-tbl-action btn-tbl-load" title="Load into Form" onclick="window.adminAppEditStudent('${email}')">
              ✏️ Edit
            </button>
            <button class="btn-tbl-action btn-tbl-del" title="Delete User from Firebase" onclick="window.adminAppDeleteStudent('${email}', '${name}', '${docKey}')">
              🗑️
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

// Global actions for user management
window.adminAppTogglePwdVisibility = function(docKey, password) {
  const elem = document.getElementById(`pwd-display-${docKey}`);
  if (!elem) return;
  elem.textContent = elem.textContent === "••••••••" ? password : "••••••••";
};

window.adminAppCopyStudentCreds = function(email) {
  const user = currentStudentList.find(s => s.email === email || s.id === email);
  if (!user) return;

  const credText = `🎓 Coralgenz Global User Authentication Access
-----------------------------------------------
👤 Name: ${user.name || user.candidateName}
📧 Email: ${user.email}
🔑 Password: ${user.password}
📘 Course: ${user.course || user.track}
-----------------------------------------------
🔒 Note: Use these credentials to authenticate and access your course Google Form.`;

  navigator.clipboard.writeText(credText).then(() => {
    showToast(`📋 Copied credentials for ${user.name || user.candidateName}!`);
  }).catch(() => {
    showToast(`Email: ${user.email}, Pass: ${user.password}`);
  });
};

window.adminAppToggleStudentAccess = async function(email, newStatus) {
  try {
    const user = currentStudentList.find(s => s.email === email || s.id === email);
    const sanitizedKey = (email || "").replace(/[^a-zA-Z0-9]/g, "_");
    const uid = user?.uid || user?.id;

    const updatePayload = {
      status: newStatus,
      accessStatus: newStatus,
      access: newStatus === "active" ? "granted" : "suspended",
      accessGranted: newStatus === "active",
      updatedAt: serverTimestamp()
    };

    const updatePromises = [];
    if (sanitizedKey) {
      updatePromises.push(setDoc(doc(db, "users", sanitizedKey), updatePayload, { merge: true }));
      updatePromises.push(setDoc(doc(db, "student_users", sanitizedKey), updatePayload, { merge: true }));
    }
    if (email) {
      updatePromises.push(setDoc(doc(db, "users", email), updatePayload, { merge: true }));
      updatePromises.push(setDoc(doc(db, "student_users", email), updatePayload, { merge: true }));
      updatePromises.push(setDoc(doc(db, "candidates", email), { status: newStatus === "active" ? "approved" : "suspended", updatedAt: new Date().toISOString() }, { merge: true }));
    }
    if (uid && uid !== sanitizedKey && uid !== email) {
      updatePromises.push(setDoc(doc(db, "users", uid), updatePayload, { merge: true }));
      updatePromises.push(setDoc(doc(db, "student_users", uid), updatePayload, { merge: true }));
    }

    await Promise.all(updatePromises);
    showToast(`Access ${newStatus === 'active' ? '🟢 GRANTED' : '🔴 SUSPENDED'} for user.`);
  } catch (err) {
    console.error("Toggle access error:", err);
    showToast("Failed to update user access status.");
  }
};

window.adminAppEditStudent = function(email) {
  const user = currentStudentList.find(s => s.email === email || s.id === email);
  if (!user) return;

  if (studentNameInput) studentNameInput.value = user.name || user.candidateName || "";
  if (studentEmailInput) studentEmailInput.value = user.email || "";
  if (studentPwdInput) studentPwdInput.value = user.password || "";
  if (studentCourseSelect) studentCourseSelect.value = user.course || "Fullstack";
  if (studentStatusSelect) studentStatusSelect.value = user.status || "active";

  updateStudentPreview();
  showToast(`Loaded "${user.name}" into editor.`);
  window.scrollTo({ top: 0, behavior: "smooth" });
};

window.adminAppDeleteStudent = async function(email, name, docKey) {
  const displayName = name || email || "this user";
  if (!confirm(`Are you sure you want to permanently delete user "${displayName}" from Firebase Authentication and Firestore?`)) {
    return;
  }

  const user = currentStudentList.find(s => s.email === email || s.id === docKey || s.id === email);
  const password = user?.password;
  const uid = user?.uid || user?.id;
  const sanitizedKey = (email || docKey || "").replace(/[^a-zA-Z0-9]/g, "_");
  const cleanEmail = (email || "").toLowerCase().trim();

  showToast(`Deleting "${displayName}" from Firebase server... ⏳`);

  try {
    // 1. Delete from Firebase Authentication (Auth Directory)
    if (cleanEmail && password) {
      try {
        const signinRes = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${_cgzVaultInit.apiKey}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: cleanEmail, password: password, returnSecureToken: true })
        });
        const signinData = await signinRes.json();
        if (signinData && signinData.idToken) {
          await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${_cgzVaultInit.apiKey}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ idToken: signinData.idToken })
          });
        }
      } catch (authErr) {
        console.warn("Auth deletion note:", authErr);
      }
    }

    // 2. Delete across all Firestore collections simultaneously
    const deletePromises = [];

    // Collection: users
    if (sanitizedKey) deletePromises.push(deleteDoc(doc(db, "users", sanitizedKey)).catch(() => {}));
    if (cleanEmail) deletePromises.push(deleteDoc(doc(db, "users", cleanEmail)).catch(() => {}));
    if (uid && uid !== sanitizedKey && uid !== cleanEmail) deletePromises.push(deleteDoc(doc(db, "users", uid)).catch(() => {}));
    if (docKey && docKey !== sanitizedKey) deletePromises.push(deleteDoc(doc(db, "users", docKey)).catch(() => {}));

    // Collection: student_users
    if (sanitizedKey) deletePromises.push(deleteDoc(doc(db, "student_users", sanitizedKey)).catch(() => {}));
    if (cleanEmail) deletePromises.push(deleteDoc(doc(db, "student_users", cleanEmail)).catch(() => {}));
    if (uid && uid !== sanitizedKey && uid !== cleanEmail) deletePromises.push(deleteDoc(doc(db, "student_users", uid)).catch(() => {}));
    if (docKey && docKey !== sanitizedKey) deletePromises.push(deleteDoc(doc(db, "student_users", docKey)).catch(() => {}));

    // Collection: candidates
    if (cleanEmail) deletePromises.push(deleteDoc(doc(db, "candidates", cleanEmail)).catch(() => {}));
    if (sanitizedKey && sanitizedKey !== cleanEmail) deletePromises.push(deleteDoc(doc(db, "candidates", sanitizedKey)).catch(() => {}));
    if (uid) deletePromises.push(deleteDoc(doc(db, "candidates", uid)).catch(() => {}));

    // Collection: interns
    if (sanitizedKey) deletePromises.push(deleteDoc(doc(db, "interns", sanitizedKey)).catch(() => {}));
    if (cleanEmail) deletePromises.push(deleteDoc(doc(db, "interns", cleanEmail)).catch(() => {}));

    await Promise.all(deletePromises);

    showToast(`🗑️ User "${displayName}" permanently deleted from Firebase!`);
  } catch (err) {
    console.error("Delete user error:", err);
    showToast("Error deleting user from Firebase.");
  }
};

// Search filter in user table
if (studentTableSearch) {
  studentTableSearch.addEventListener("input", () => {
    const q = studentTableSearch.value.toLowerCase().trim();
    if (!q) {
      renderUsersTable(currentStudentList);
      return;
    }
    const filtered = currentStudentList.filter(s => {
      const name = (s.name || s.candidateName || "").toLowerCase();
      const email = (s.email || "").toLowerCase();
      const course = (s.course || s.track || "").toLowerCase();
      return name.includes(q) || email.includes(q) || course.includes(q);
    });
    renderUsersTable(filtered);
  });
}

// Button actions
if (btnGenStrongPwd) {
  btnGenStrongPwd.addEventListener("click", () => {
    const pwd = generateStrongPassword();
    showToast(`Generated random password: ${pwd} 🎲`);
  });
}

if (btnQuickSampleStudent) {
  btnQuickSampleStudent.addEventListener("click", () => {
    const sampleUsers = [
      { name: "Karthick Krishna", email: "karthick.krishna@gmail.com", course: "Fullstack" },
      { name: "Vikram Rathore", email: "vikram.rathore@gmail.com", course: "Java" },
      { name: "Priya Soundar", email: "priya.soundar@gmail.com", course: "Python" },
      { name: "Rahul Varma", email: "rahul.varma@gmail.com", course: "C" },
      { name: "Sneha Reddy", email: "sneha.reddy@gmail.com", course: "Web Development" }
    ];

    const pick = sampleUsers[Math.floor(Math.random() * sampleUsers.length)];
    if (studentNameInput) studentNameInput.value = pick.name;
    if (studentEmailInput) studentEmailInput.value = pick.email;
    if (studentCourseSelect) studentCourseSelect.value = pick.course;
    generateStrongPassword();
    updateStudentPreview();
    showToast(`Loaded sample user profile for ${pick.name}! 🚀`);
  });
}

if (btnResetStudentForm) {
  btnResetStudentForm.addEventListener("click", () => {
    if (studentAuthForm) studentAuthForm.reset();
    if (studentNameInput) studentNameInput.value = "";
    if (studentEmailInput) studentEmailInput.value = "";
    if (studentPwdInput) studentPwdInput.value = "";
    updateStudentPreview();
    if (studentStatusAlert) studentStatusAlert.style.display = "none";
    showToast("Form reset.");
  });
}

if (btnCopyStudentCreds) {
  btnCopyStudentCreds.addEventListener("click", () => {
    const name = studentNameInput?.value.trim() || "User";
    const email = studentEmailInput?.value.trim() || "user@gmail.com";
    const pwd = studentPwdInput?.value.trim() || "••••••••";
    const course = studentCourseSelect?.value || "Fullstack";

    const text = `🎓 Coralgenz Global User Authentication Access
-----------------------------------------------
👤 Name: ${name}
📧 Email: ${email}
🔑 Password: ${pwd}
📘 Course: ${course}
-----------------------------------------------
🔒 Note: Keep your credentials secure.`;

    navigator.clipboard.writeText(text).then(() => {
      showToast("📋 User login credentials copied to clipboard!");
    }).catch(() => {
      showToast(`Email: ${email}, Pass: ${pwd}`);
    });
  });
}

// ==========================================
// 8. COURSE GOOGLE FORMS CONFIGURATOR (SETTINGS & COURSES)
// ==========================================
function showFormsConfigAlert(type, msg) {
  if (!formsConfigStatusAlert) return;
  formsConfigStatusAlert.className = `admin-status-box status-${type}`;
  formsConfigStatusAlert.innerHTML = `<div>${msg}</div>`;
  formsConfigStatusAlert.style.display = "block";
}

async function loadCourseFormsConfig() {
  try {
    let loadedData = null;

    // 1. Try loading from settings/course_forms
    try {
      const settingsSnap = await getDoc(doc(db, "settings", "course_forms"));
      if (settingsSnap.exists()) {
        loadedData = settingsSnap.data();
      }
    } catch(e) {}

    // 2. Try loading from individual courses collection documents
    try {
      const [javaDoc, pythonDoc, cDoc, webDoc, fullstackDoc] = await Promise.all([
        getDoc(doc(db, "courses", "java")),
        getDoc(doc(db, "courses", "python")),
        getDoc(doc(db, "courses", "c")),
        getDoc(doc(db, "courses", "web")),
        getDoc(doc(db, "courses", "fullstack"))
      ]);

      const coursesMap = {};
      if (javaDoc.exists() && javaDoc.data().formUrl) coursesMap.java = javaDoc.data().formUrl;
      if (pythonDoc.exists() && pythonDoc.data().formUrl) coursesMap.python = pythonDoc.data().formUrl;
      if (cDoc.exists() && cDoc.data().formUrl) coursesMap.c = cDoc.data().formUrl;
      if (webDoc.exists() && webDoc.data().formUrl) coursesMap.webdev = webDoc.data().formUrl;
      if (fullstackDoc.exists() && fullstackDoc.data().formUrl) coursesMap.fullstack = fullstackDoc.data().formUrl;

      if (Object.keys(coursesMap).length > 0) {
        loadedData = { ...(loadedData || {}), ...coursesMap };
      }
    } catch(e) {}

    // 3. Fallback: app_config/course_forms
    if (!loadedData) {
      try {
        const appConfigSnap = await getDoc(doc(db, "app_config", "course_forms"));
        if (appConfigSnap.exists()) {
          loadedData = appConfigSnap.data();
        }
      } catch(e) {}
    }

    if (loadedData) {
      activeFormsMap = { ...DEFAULT_COURSE_FORMS, ...loadedData };
      if (formUrlJava) formUrlJava.value = loadedData.java || DEFAULT_COURSE_FORMS.java;
      if (formUrlPython) formUrlPython.value = loadedData.python || DEFAULT_COURSE_FORMS.python;
      if (formUrlC) formUrlC.value = loadedData.c || DEFAULT_COURSE_FORMS.c;
      if (formUrlWebdev) formUrlWebdev.value = loadedData.web || loadedData.webdev || loadedData["web development"] || DEFAULT_COURSE_FORMS.webdev;
      if (formUrlFullstack) formUrlFullstack.value = loadedData.fullstack || DEFAULT_COURSE_FORMS.fullstack;
    } else {
      resetCourseFormsToDefaults();
    }
  } catch (err) {
    console.warn("Could not load course forms config from Firestore, using defaults:", err);
    resetCourseFormsToDefaults();
  }
}

function resetCourseFormsToDefaults() {
  activeFormsMap = { ...DEFAULT_COURSE_FORMS };
  if (formUrlJava) formUrlJava.value = DEFAULT_COURSE_FORMS.java;
  if (formUrlPython) formUrlPython.value = DEFAULT_COURSE_FORMS.python;
  if (formUrlC) formUrlC.value = DEFAULT_COURSE_FORMS.c;
  if (formUrlWebdev) formUrlWebdev.value = DEFAULT_COURSE_FORMS.webdev;
  if (formUrlFullstack) formUrlFullstack.value = DEFAULT_COURSE_FORMS.fullstack;
  updateStudentPreview();
}

if (btnLoadDefaultForms) {
  btnLoadDefaultForms.addEventListener("click", () => {
    resetCourseFormsToDefaults();
    showToast("Reset to default dummy Google Form links.");
  });
}

async function saveCourseFormsConfig(e) {
  if (e) e.preventDefault();

  const javaUrl = (formUrlJava?.value || DEFAULT_COURSE_FORMS.java).trim();
  const pythonUrl = (formUrlPython?.value || DEFAULT_COURSE_FORMS.python).trim();
  const cUrl = (formUrlC?.value || DEFAULT_COURSE_FORMS.c).trim();
  const webdevUrl = (formUrlWebdev?.value || DEFAULT_COURSE_FORMS.webdev).trim();
  const fullstackUrl = (formUrlFullstack?.value || DEFAULT_COURSE_FORMS.fullstack).trim();
  const nowIso = new Date().toISOString();

  const configData = {
    java: javaUrl,
    python: pythonUrl,
    c: cUrl,
    web: webdevUrl,
    webdev: webdevUrl,
    "web development": webdevUrl,
    fullstack: fullstackUrl,
    updatedAt: serverTimestamp()
  };

  activeFormsMap = { ...activeFormsMap, ...configData };

  if (btnSaveCourseForms) {
    btnSaveCourseForms.disabled = true;
    btnSaveCourseForms.innerHTML = `<span>Saving to settings & courses... ⏳</span>`;
  }

  try {
    // 1. Save to settings/course_forms in exact structure
    await setDoc(doc(db, "settings", "course_forms"), {
      java: javaUrl,
      python: pythonUrl,
      c: cUrl,
      web: webdevUrl,
      fullstack: fullstackUrl,
      updatedAt: nowIso
    }, { merge: true });

    // 2. Save to courses collection in exact structure
    await setDoc(doc(db, "courses", "java"), {
      title: "Java Developer",
      formUrl: javaUrl
    }, { merge: true });

    await setDoc(doc(db, "courses", "python"), {
      title: "Python Developer",
      formUrl: pythonUrl
    }, { merge: true });

    await setDoc(doc(db, "courses", "c"), {
      title: "C Programming & Systems",
      formUrl: cUrl
    }, { merge: true });

    await setDoc(doc(db, "courses", "web"), {
      title: "Frontend Web Engineering",
      formUrl: webdevUrl
    }, { merge: true });

    await setDoc(doc(db, "courses", "fullstack"), {
      title: "Full Stack Web Development",
      formUrl: fullstackUrl
    }, { merge: true });

    // 3. Also sync to app_config/course_forms & course_forms/links for complete system compatibility
    await setDoc(doc(db, "app_config", "course_forms"), configData, { merge: true });
    await setDoc(doc(db, "course_forms", "links"), configData, { merge: true });

    showFormsConfigAlert("success", "✅ <strong>Course Google Forms Links Synced to Firebase!</strong><br>Successfully updated <code>settings/course_forms</code>, <code>courses</code> collection, and <code>app_config</code> in Firebase Firestore.");
    showToast("🎉 Google Form links saved to Firebase settings & courses!");
    updateStudentPreview();
  } catch (err) {
    console.error("Save course forms error:", err);
    showFormsConfigAlert("error", `Firebase Write Error: ${err.message}`);
    showToast("⚠️ Firebase Firestore error saving course forms.");
  } finally {
    if (btnSaveCourseForms) {
      btnSaveCourseForms.disabled = false;
      btnSaveCourseForms.innerHTML = `<span>💾 Save Course Google Form Links to Firebase</span><span>🚀</span>`;
    }
  }
}

if (courseFormsConfigForm) {
  courseFormsConfigForm.addEventListener("submit", saveCourseFormsConfig);
}

// ==========================================
// 9. CERTIFICATE & QR GENERATOR ENGINE
// ==========================================
function generateSerialId() {
  const randomNum = Math.floor(1000 + Math.random() * 9000);
  const serial = `CG-MSME-2026-CERT-${randomNum}`;
  if (candSerialInput) candSerialInput.value = serial;
  updateLivePreview();
  return serial;
}

function generateVerificationQR(candidateData, targetBaseUrl) {
  if (!qrCanvasBox) return "";

  currentSaltedToken = generateSaltedHashToken(candidateData);

  let base = (targetBaseUrl || "https://internships.coralgenz.co.in/").trim();
  if (base.includes("?")) base = base.split("?")[0];
  const cleanBase = base.replace(/\/$/, "");
  const fullVerificationUrl = `${cleanBase}/?v=${encodeURIComponent(currentSaltedToken)}`;

  qrCanvasBox.innerHTML = "";

  try {
    if (typeof QRCode !== "undefined") {
      qrCodeInstance = new QRCode(qrCanvasBox, {
        text: fullVerificationUrl,
        width: 140,
        height: 140,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.M
      });
    } else {
      const img = document.createElement("img");
      img.src = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&ecc=M&margin=1&data=${encodeURIComponent(fullVerificationUrl)}`;
      img.alt = `QR Code`;
      qrCanvasBox.appendChild(img);
    }
  } catch (err) {
    console.error("QR Code Generation Error:", err);
    const img = document.createElement("img");
    img.src = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&ecc=M&margin=1&data=${encodeURIComponent(fullVerificationUrl)}`;
    img.alt = `QR Code`;
    qrCanvasBox.appendChild(img);
  }

  return fullVerificationUrl;
}

function updateLivePreview() {
  const name = candNameInput?.value.trim() || "Karthick Krishna";
  const email = candEmailInput?.value.trim() || "candidate@gmail.com";
  const track = candTrackInput?.value || "Fullstack";
  const serialId = candSerialInput?.value.trim() || "CG-MSME-2026-CERT-8842";
  const duration = "1 Month";
  const issueDate = candIssueDateInput?.value.trim() || "August 2026";
  const verifyUrl = candVerifyUrlInput?.value.trim() || "https://internships.coralgenz.co.in/";

  if (prevName) prevName.textContent = name;
  if (prevEmail) prevEmail.textContent = email;
  if (prevTrack) prevTrack.textContent = track;
  if (prevCertId) prevCertId.textContent = serialId;
  if (prevIssueDate) prevIssueDate.textContent = issueDate;

  const candidatePayload = {
    name,
    candidateName: name,
    email,
    track,
    course: track,
    serialNumber: serialId,
    certId: serialId,
    duration: "1 Month",
    issueDate,
    status: "100% Completed • MSME Verified Deliverables",
    issuingAuthority: "Coralgenz Global, Coimbatore, Tamil Nadu, India",
    msmeRegNo: "UDYAM-TN-03-0189422"
  };

  generateVerificationQR(candidatePayload, verifyUrl);
}

// Expose globally
window.updateLivePreview = updateLivePreview;

[candNameInput, candEmailInput, candTrackInput, candSerialInput, candIssueDateInput, candVerifyUrlInput].forEach(elem => {
  if (elem) {
    elem.addEventListener("input", updateLivePreview);
    elem.addEventListener("change", updateLivePreview);
  }
});

async function saveCertificateToFirebase(e) {
  if (e) e.preventDefault();

  const name = candNameInput?.value.trim();
  const email = candEmailInput?.value.trim().toLowerCase();
  const track = candTrackInput?.value || "Fullstack";
  let serialId = candSerialInput?.value.trim();
  const duration = "1 Month";
  const issueDate = candIssueDateInput?.value.trim() || "August 2026";
  const verifyBaseUrl = candVerifyUrlInput?.value.trim() || "https://internships.coralgenz.co.in/";

  if (!name || !email || !track) {
    showCertAlert("error", "Please fill in Candidate Name, Email, and Track.");
    return;
  }

  if (!serialId) serialId = generateSerialId();

  const certData = {
    name: name,
    candidateName: name,
    email: email,
    track: track,
    course: track,
    serialNumber: serialId,
    certId: serialId,
    duration: "1 Month",
    issueDate: issueDate,
    status: "100% Completed • MSME Verified Deliverables",
    issuingAuthority: "Coralgenz Global, Coimbatore, Tamil Nadu, India",
    msmeRegNo: "UDYAM-TN-03-0189422",
    updatedAt: serverTimestamp(),
    createdAt: serverTimestamp()
  };

  const saltedToken = generateSaltedHashToken(certData);
  let base = verifyBaseUrl.includes("?") ? verifyBaseUrl.split("?")[0] : verifyBaseUrl;
  const fullVerifyUrl = `${base.replace(/\/$/, "")}/?v=${encodeURIComponent(saltedToken)}`;

  certData.saltedToken = saltedToken;
  certData.verificationUrl = fullVerifyUrl;

  if (btnSaveFirebase) {
    btnSaveFirebase.disabled = true;
    btnSaveFirebase.innerHTML = `<span>Saving to Firebase... ⏳</span>`;
  }

  try {
    await setDoc(doc(db, "certificates", serialId), certData, { merge: true });
    const sanitizedEmailKey = email.replace(/[^a-zA-Z0-9]/g, "_");
    await setDoc(doc(db, "interns", sanitizedEmailKey), certData, { merge: true });

    showCertAlert("success", `✅ <strong>Certificate Issued & Synced!</strong><br>Candidate: <strong>${name}</strong> (${serialId})<br>Track: <strong>${track}</strong><br>Saved to Firebase Firestore!`);
    showToast(`🎉 Certificate ${serialId} synced to Firebase!`);
  } catch (err) {
    console.error("Firebase write error:", err);
    showCertAlert("error", `Firebase Write Error: ${err.message}.`);
    showToast("⚠️ Firebase Firestore sync error.");
  } finally {
    if (btnSaveFirebase) {
      btnSaveFirebase.disabled = false;
      btnSaveFirebase.innerHTML = `<span>💾 Save Certificate to Firebase</span><span>🚀</span>`;
    }
  }
}

function showCertAlert(type, msg) {
  if (!certStatusAlert) return;
  certStatusAlert.className = `admin-status-box status-${type}`;
  certStatusAlert.innerHTML = `<div>${msg}</div>`;
  certStatusAlert.style.display = "block";
}

if (certForm) {
  certForm.addEventListener("submit", saveCertificateToFirebase);
}

// Real-time Firestore Listener for Certificates
function listenToFirebaseCertificates() {
  try {
    const certsCol = collection(db, "certificates");

    onSnapshot(certsCol, (snapshot) => {
      currentCertsList = [];
      snapshot.forEach(docSnap => {
        currentCertsList.push({ id: docSnap.id, ...docSnap.data() });
      });

      if (metricTotalCerts) metricTotalCerts.textContent = currentCertsList.length;
      if (tabCertCount) tabCertCount.textContent = currentCertsList.length;

      renderCertificatesTable(currentCertsList);
    }, (error) => {
      console.warn("Firestore certificates listener snapshot notice:", error);
      renderCertificatesTable([]);
    });
  } catch (err) {
    console.error("Firestore certificates listener initialization:", err);
    renderCertificatesTable([]);
  }
}

function renderCertificatesTable(records) {
  if (!certTableBody) return;

  if (records.length === 0) {
    certTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="td-empty" style="text-align: center; padding: 2rem 1rem; color: #94a3b8;">
          No certificates issued yet in Firebase Firestore.<br>Fill the form above and click <strong>"Save Certificate to Firebase"</strong> to issue the first certificate.
        </td>
      </tr>
    `;
    return;
  }

  certTableBody.innerHTML = records.map(cert => {
    const certName = cert.name || cert.candidateName || "Candidate";
    const certEmail = cert.email || "—";
    const certTrack = cert.track || "Full Stack Web Development";
    const certSerial = cert.serialNumber || cert.certId || cert.id;
    const certDate = cert.issueDate || "2026";
    
    let saltedToken = cert.saltedToken;
    if (!saltedToken) {
      saltedToken = generateSaltedHashToken({
        name: certName,
        candidateName: certName,
        email: certEmail,
        track: certTrack,
        serialNumber: certSerial,
        certId: certSerial,
        duration: cert.duration || "8-12 Weeks • Remote",
        issueDate: certDate,
        status: cert.status || "100% Completed",
        msmeRegNo: cert.msmeRegNo || "UDYAM-TN-03-0189422"
      });
    }

    const verifyUrl = `https://internships.coralgenz.co.in/?v=${encodeURIComponent(saltedToken)}`;

    return `
      <tr data-serial="${certSerial}">
        <td>
          <div class="td-candidate-info">
            <span class="td-cand-name">${certName}</span>
            <span class="td-cand-email">${certEmail}</span>
          </div>
        </td>
        <td>${certTrack}</td>
        <td><span class="serial-tag">${certSerial}</span></td>
        <td>${certDate}</td>
        <td>
          <div class="table-mini-qr" title="Click to view & download QR" onclick="window.adminAppLoadCertRecord('${certSerial}')">
            <img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&ecc=M&margin=1&data=${encodeURIComponent(verifyUrl)}" alt="QR Code">
          </div>
        </td>
        <td>
          <div class="table-action-btns">
            <button class="btn-tbl-action btn-tbl-load" title="Load details into Editor" onclick="window.adminAppLoadCertRecord('${certSerial}')">
              ✏️ Edit
            </button>
            <button class="btn-tbl-action btn-tbl-copy" title="Copy Verification URL" onclick="window.adminAppCopyCertLink('${certSerial}')">
              🔗 Copy
            </button>
            <button class="btn-tbl-action btn-tbl-del" title="Delete from Firebase" onclick="window.adminAppDeleteCertRecord('${certSerial}')">
              🗑️
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

window.adminAppLoadCertRecord = function(serialId) {
  const record = currentCertsList.find(c => (c.serialNumber === serialId || c.certId === serialId || c.id === serialId));
  if (!record) return;

  if (candNameInput) candNameInput.value = record.name || record.candidateName || "";
  if (candEmailInput) candEmailInput.value = record.email || "";
  if (candTrackInput) candTrackInput.value = record.track || record.course || "Fullstack";
  if (candSerialInput) candSerialInput.value = record.serialNumber || record.certId || serialId;
  if (candIssueDateInput) candIssueDateInput.value = record.issueDate || "August 2026";

  updateLivePreview();
  showToast(`Loaded "${record.name}" into certificate editor!`);
};

window.adminAppCopyCertLink = function(serialId) {
  const record = currentCertsList.find(c => (c.serialNumber === serialId || c.certId === serialId || c.id === serialId));
  let token = record?.saltedToken;
  if (!token && record) token = generateSaltedHashToken(record);
  const url = token 
    ? `https://internships.coralgenz.co.in/?v=${encodeURIComponent(token)}`
    : `https://internships.coralgenz.co.in/?id=${encodeURIComponent(serialId)}`;

  navigator.clipboard.writeText(url).then(() => {
    showToast(`Copied Verification Link for ${serialId}! 🔗`);
  }).catch(() => {
    showToast(`Verification Link: ${url}`);
  });
};

window.adminAppDeleteCertRecord = async function(serialId) {
  if (!confirm(`Are you sure you want to delete certificate "${serialId}" from Firebase Firestore?`)) return;

  try {
    await deleteDoc(doc(db, "certificates", serialId));
    showToast(`🗑️ Certificate ${serialId} removed from Firebase.`);
  } catch (err) {
    console.error("Delete error:", err);
    showToast("Error deleting certificate from Firestore.");
  }
};

if (certTableSearchInput) {
  certTableSearchInput.addEventListener("input", () => {
    const q = certTableSearchInput.value.toLowerCase().trim();
    if (!q) {
      renderCertificatesTable(currentCertsList);
      return;
    }
    const filtered = currentCertsList.filter(c => {
      const name = (c.name || c.candidateName || "").toLowerCase();
      const email = (c.email || "").toLowerCase();
      const track = (c.track || "").toLowerCase();
      const serial = (c.serialNumber || c.certId || c.id || "").toLowerCase();
      return name.includes(q) || email.includes(q) || track.includes(q) || serial.includes(q);
    });
    renderCertificatesTable(filtered);
  });
}

// Scanned verification URL query handler (NO CRYPTOGRAPHIC SALT OR GRADE EXPOSED)
async function checkUrlParamsForVerification() {
  const params = new URLSearchParams(window.location.search);
  const paramVal = (params.get("v") || params.get("token") || params.get("id") || params.get("verify") || params.get("email") || "").trim();
  if (!paramVal) return;

  // 1. If Salted Token
  if (isSaltedHashToken(paramVal)) {
    const verified = verifyAndDecodeSaltedHash(paramVal);
    if (verified.valid && verified.data) {
      const candidateData = verified.data;
      if (candNameInput) candNameInput.value = candidateData.name || candidateData.candidateName || "";
      if (candEmailInput) candEmailInput.value = candidateData.email || "";
      if (candTrackInput) candTrackInput.value = candidateData.track || candidateData.course || "Fullstack";
      if (candSerialInput) candSerialInput.value = candidateData.serialNumber || candidateData.certId || "";
      if (candIssueDateInput) candIssueDateInput.value = candidateData.issueDate || "August 2026";

      updateLivePreview();
      showCertAlert("success", `✅ <strong>Authentic Verified Candidate Record</strong><br>Candidate: <strong>${candidateData.name || candidateData.candidateName}</strong> (${candidateData.email})<br>Internship Track: <strong>${candidateData.track}</strong><br>Duration: <strong>1 Month</strong><br>Serial ID: <strong>${candidateData.serialNumber || candidateData.certId}</strong><br>Status: Verified Authenticated Record`);
      showToast(`✅ Verified record for ${candidateData.name || candidateData.candidateName}!`);
      return;
    } else {
      showCertAlert("error", `❌ <strong>Verification Notice</strong><br>${verified.message || "Invalid certificate record."}`);
      return;
    }
  }

  // 2. Direct Serial lookup
  const serialId = paramVal;
  if (candSerialInput) candSerialInput.value = serialId;

  try {
    const docRef = doc(db, "certificates", serialId);
    const docSnap = await getDoc(docRef);

    if (docSnap.exists()) {
      const candidateData = docSnap.data();
      if (candNameInput) candNameInput.value = candidateData.name || candidateData.candidateName || "";
      if (candEmailInput) candEmailInput.value = candidateData.email || "";
      if (candTrackInput) candTrackInput.value = candidateData.track || candidateData.course || "Fullstack";
      if (candSerialInput) candSerialInput.value = candidateData.serialNumber || candidateData.certId || serialId;
      if (candIssueDateInput) candIssueDateInput.value = candidateData.issueDate || "August 2026";

      updateLivePreview();
      showCertAlert("success", `✅ <strong>Authentic Verified Candidate Record</strong><br>Candidate: <strong>${candidateData.name || candidateData.candidateName}</strong> (${candidateData.email})<br>Internship Track: <strong>${candidateData.track}</strong><br>Duration: <strong>1 Month</strong><br>Serial ID: <strong>${candidateData.serialNumber || candidateData.certId || serialId}</strong>`);
      showToast(`✅ Verified certificate for ${candidateData.name || candidateData.candidateName}!`);
    } else {
      showCertAlert("error", `❌ <strong>Certificate Not Found</strong><br>The certificate serial <strong>${serialId}</strong> was not found in the database.`);
    }
  } catch (err) {
    console.error("Verification lookup error:", err);
  }
}

// Certificate Action buttons
if (btnGenNewId) {
  btnGenNewId.addEventListener("click", () => {
    const newId = generateSerialId();
    showToast(`Generated new Serial ID: ${newId}`);
  });
}

if (btnQuickSample) {
  btnQuickSample.addEventListener("click", () => {
    const samples = [
      { name: "Karthick Krishna", email: "karthick.krishna@gmail.com", track: "Fullstack" },
      { name: "Aravind Swaminathan", email: "aravind.swami@gmail.com", track: "Python" },
      { name: "Priya Soundararajan", email: "priya.soundar@gmail.com", track: "Java" },
      { name: "Rahul Varma", email: "rahul.varma@gmail.com", track: "C" },
      { name: "Sneha Reddy", email: "sneha.reddy@gmail.com", track: "Web Development" }
    ];
    const pick = samples[Math.floor(Math.random() * samples.length)];
    if (candNameInput) candNameInput.value = pick.name;
    if (candEmailInput) candEmailInput.value = pick.email;
    if (candTrackInput) candTrackInput.value = pick.track;
    generateSerialId();
    updateLivePreview();
    showToast(`Loaded sample profile for ${pick.name}! ✨`);
  });
}

if (btnResetForm) {
  btnResetForm.addEventListener("click", () => {
    if (certForm) certForm.reset();
    generateSerialId();
    updateLivePreview();
    if (certStatusAlert) certStatusAlert.style.display = "none";
    showToast("Certificate form reset.");
  });
}

if (btnPreviewCert) {
  btnPreviewCert.addEventListener("click", () => {
    updateLivePreview();
    showToast("Updated Live Certificate Card Preview! 👁️");
  });
}

if (btnDownloadQrImg) {
  btnDownloadQrImg.addEventListener("click", () => {
    const serial = candSerialInput?.value.trim() || "CG-MSME-2026";
    const canvas = qrCanvasBox?.querySelector("canvas");
    const img = qrCanvasBox?.querySelector("img");

    if (canvas) {
      const a = document.createElement("a");
      a.href = canvas.toDataURL("image/png");
      a.download = `Coralgenz-QR-${serial}.png`;
      a.click();
      showToast(`📥 QR Code PNG downloaded for ${serial}!`);
    } else if (img && img.src) {
      const a = document.createElement("a");
      a.href = img.src;
      a.download = `Coralgenz-QR-${serial}.png`;
      a.click();
      showToast(`📥 Downloading QR Code...`);
    }
  });
}

if (btnPrintAdminCert) {
  btnPrintAdminCert.addEventListener("click", () => {
    showToast("Preparing Printable Certificate (PDF)... 🖨️");
    setTimeout(() => window.print(), 400);
  });
}

if (btnCopyPublicLink) {
  btnCopyPublicLink.addEventListener("click", () => {
    const base = (candVerifyUrlInput?.value.trim() || "https://internships.coralgenz.co.in/").split("?")[0].replace(/\/$/, "");
    const url = currentSaltedToken 
      ? `${base}/?v=${encodeURIComponent(currentSaltedToken)}`
      : `${base}/?id=${encodeURIComponent(candSerialInput?.value.trim() || "CG-MSME-2026")}`;

    navigator.clipboard.writeText(url).then(() => {
      showToast("Verification Link copied! 🔗");
    }).catch(() => {
      showToast(`Link: ${url}`);
    });
  });
}

// ==========================================
// 10. INITIALIZATION
// ==========================================
function initAdminApp() {
  checkAdminAuthSession();
  initTabNavigation();
  updateStudentPreview();
  loadCourseFormsConfig();
  listenToFirebaseUsers();

  generateSerialId();
  updateLivePreview();
  listenToFirebaseCertificates();
  checkUrlParamsForVerification();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initAdminApp);
} else {
  initAdminApp();
}
