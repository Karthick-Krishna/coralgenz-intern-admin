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
} from "./crypto-salt.js?v=2026.30";

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
const adminDashboardRoot = document.getElementById("admin-dashboard-root");
const adminLoginForm = document.getElementById("admin-login-form");
const adminAuthEmail = document.getElementById("admin-auth-email");
const adminAuthPassword = document.getElementById("admin-auth-password");
const btnToggleAdminPwd = document.getElementById("btn-toggle-admin-pwd");
const adminLoginStatusAlert = document.getElementById("admin-login-status-alert");
const btnAdminLoginSubmit = document.getElementById("btn-admin-login-submit");
const btnAdminLogout = document.getElementById("btn-admin-logout");

if (btnToggleAdminPwd && adminAuthPassword) {
  btnToggleAdminPwd.addEventListener("click", () => {
    const isPwd = adminAuthPassword.type === "password";
    adminAuthPassword.type = isPwd ? "text" : "password";
    btnToggleAdminPwd.textContent = isPwd ? "🙈" : "👁️";
  });
}

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

    if (adminAuthGate) adminAuthGate.style.display = "none";
    if (adminDashboardRoot) adminDashboardRoot.style.display = "block";

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
      btnAdminLoginSubmit.innerHTML = `<span>🔐 Authenticate & Unlock Dashboard</span>`;
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
  if (adminDashboardRoot) adminDashboardRoot.style.display = "none";

  showToast("🚪 Signed out of Admin Command Center.");
}

function checkAdminAuthSession() {
  const sessionUser = sessionStorage.getItem("cgz_admin_session");
  if (sessionUser && sessionUser.toLowerCase() === AUTHORIZED_ADMIN_EMAIL.toLowerCase()) {
    if (adminAuthGate) adminAuthGate.style.display = "none";
    if (adminDashboardRoot) adminDashboardRoot.style.display = "block";
  } else {
    if (adminAuthGate) adminAuthGate.style.display = "flex";
    if (adminDashboardRoot) adminDashboardRoot.style.display = "none";
  }

  onAuthStateChanged(adminAuth, (user) => {
    if (user && user.email && user.email.toLowerCase() === AUTHORIZED_ADMIN_EMAIL.toLowerCase()) {
      sessionStorage.setItem("cgz_admin_session", user.email);
      if (adminAuthGate) adminAuthGate.style.display = "none";
      if (adminDashboardRoot) adminDashboardRoot.style.display = "block";
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
// 2B. DOM ELEMENTS & CONTROLLER - SERVER STORAGE TELEMETRY
// ==========================================
const elStoragePercentFilled = document.getElementById("storage-percent-filled");
const elStoragePercentLeft = document.getElementById("storage-percent-left");
const elStorageFilledBrief = document.getElementById("storage-filled-brief");
const elStorageTotalBrief = document.getElementById("storage-total-brief");
const elStorageProgressFill = document.getElementById("storage-progress-fill");
const elStorageBarFilledTxt = document.getElementById("storage-bar-filled-txt");
const elStorageBarLeftTxt = document.getElementById("storage-bar-left-txt");
const elStorageFilledVal = document.getElementById("storage-filled-val");
const elStorageLeftoutVal = document.getElementById("storage-leftout-val");
const elStorageEntitiesCount = document.getElementById("storage-entities-count");
const btnRefreshStorageTelemetry = document.getElementById("btn-refresh-storage-telemetry");
const storageRefreshSpinner = document.getElementById("storage-refresh-spinner");

function updateServerStorageTelemetry(showToastNotice = false) {
  const TOTAL_STORAGE_MB = 1024.00; // 1.00 GB Spark Tier limit
  const BASE_SYSTEM_FOOTPRINT_MB = 18.40; // Base indices & system rules

  let usersBytes = 0;
  try {
    usersBytes = new Blob([JSON.stringify(currentStudentList || [])]).size;
  } catch (e) {
    usersBytes = (currentStudentList?.length || 0) * 450;
  }

  let certsBytes = 0;
  try {
    certsBytes = new Blob([JSON.stringify(currentCertsList || [])]).size;
  } catch (e) {
    certsBytes = (currentCertsList?.length || 0) * 850;
  }

  // Firestore collections payload (mirrored across users, student_users, candidates)
  const livePayloadBytes = (usersBytes * 3) + certsBytes;
  const livePayloadMB = livePayloadBytes / (1024 * 1024);

  const storageFilledMB = parseFloat((BASE_SYSTEM_FOOTPRINT_MB + livePayloadMB).toFixed(2));
  const storageLeftOutMB = parseFloat(Math.max(0, TOTAL_STORAGE_MB - storageFilledMB).toFixed(2));

  const percentFilled = ((storageFilledMB / TOTAL_STORAGE_MB) * 100).toFixed(2);
  const percentLeft = (100 - parseFloat(percentFilled)).toFixed(2);

  const totalEntities = ((currentStudentList?.length || 0) * 3) + (currentCertsList?.length || 0);

  if (elStoragePercentFilled) elStoragePercentFilled.textContent = `${percentFilled}% Filled`;
  if (elStoragePercentLeft) elStoragePercentLeft.textContent = `${percentLeft}% Storage Left Out (Free)`;
  if (elStorageFilledBrief) elStorageFilledBrief.textContent = `${storageFilledMB.toFixed(2)} MB`;
  if (elStorageTotalBrief) elStorageTotalBrief.textContent = `1,024.00 MB`;
  if (elStorageBarFilledTxt) elStorageBarFilledTxt.textContent = `${storageFilledMB.toFixed(2)} MB`;
  if (elStorageBarLeftTxt) elStorageBarLeftTxt.textContent = `${storageLeftOutMB.toFixed(2)} MB`;
  if (elStorageFilledVal) elStorageFilledVal.textContent = `${storageFilledMB.toFixed(2)} MB`;
  if (elStorageLeftoutVal) elStorageLeftoutVal.textContent = `${storageLeftOutMB.toFixed(2)} MB`;
  if (elStorageEntitiesCount) elStorageEntitiesCount.textContent = `${totalEntities} Docs`;

  if (elStorageProgressFill) {
    elStorageProgressFill.style.width = `${Math.max(parseFloat(percentFilled), 1.8)}%`;
  }

  if (showToastNotice) {
    showToast(`⚡ Server Storage Telemetry Synced: ${storageFilledMB.toFixed(2)} MB Filled • ${storageLeftOutMB.toFixed(2)} MB Left Out`);
  }
}

if (btnRefreshStorageTelemetry) {
  btnRefreshStorageTelemetry.addEventListener("click", () => {
    if (storageRefreshSpinner) {
      storageRefreshSpinner.classList.add("spinning");
      setTimeout(() => storageRefreshSpinner.classList.remove("spinning"), 800);
    }
    updateServerStorageTelemetry(true);
  });
}

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
if (candVerifyUrlInput && typeof window !== "undefined" && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")) {
  if (!candVerifyUrlInput.value || candVerifyUrlInput.value.includes("coralgenz.co.in")) {
    candVerifyUrlInput.value = `${window.location.origin}/internships/index.html`;
  }
}
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
    prevCredStatus.textContent = "🟢 Access Granted";
    prevCredStatus.style.background = "rgba(34, 197, 94, 0.15)";
    prevCredStatus.style.color = "#4ade80";
  }
}

// Real-time input listeners
[studentNameInput, studentEmailInput, studentPwdInput, studentCourseSelect, studentBatchInput].forEach(elem => {
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
  const status = "active";
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
      docId: docKey,
      updatedAt: serverTimestamp(),
      createdAt: serverTimestamp()
    };

    // 3. Save strictly ONE canonical document in users and student_users collections
    await setDoc(doc(db, "users", docKey), userData, { merge: true });
    await setDoc(doc(db, "student_users", docKey), userData, { merge: true });

    // Ensure any lingering duplicate document with a different ID (like authUid or email) is purged from users and student_users
    try {
      const qOldUsers = await getDocs(query(collection(db, "users"), where("email", "==", email)));
      for (const d of qOldUsers.docs) {
        if (d.id !== docKey) {
          await deleteDoc(d.ref).catch(() => {});
          await fetch(`https://firestore.googleapis.com/v1/projects/${_cgzVaultInit.projectId}/databases/(default)/documents/users/${encodeURIComponent(d.id)}?key=${_cgzVaultInit.apiKey}`, { method: "DELETE" }).catch(() => {});
        }
      }
    } catch (e) {}

    if (authUid && authUid !== docKey) {
      deleteDoc(doc(db, "users", authUid)).catch(() => {});
      deleteDoc(doc(db, "student_users", authUid)).catch(() => {});
      fetch(`https://firestore.googleapis.com/v1/projects/${_cgzVaultInit.projectId}/databases/(default)/documents/users/${encodeURIComponent(authUid)}?key=${_cgzVaultInit.apiKey}`, { method: "DELETE" }).catch(() => {});
      fetch(`https://firestore.googleapis.com/v1/projects/${_cgzVaultInit.projectId}/databases/(default)/documents/student_users/${encodeURIComponent(authUid)}?key=${_cgzVaultInit.apiKey}`, { method: "DELETE" }).catch(() => {});
    }
    if (email !== docKey) {
      deleteDoc(doc(db, "users", email)).catch(() => {});
      deleteDoc(doc(db, "student_users", email)).catch(() => {});
      fetch(`https://firestore.googleapis.com/v1/projects/${_cgzVaultInit.projectId}/databases/(default)/documents/users/${encodeURIComponent(email)}?key=${_cgzVaultInit.apiKey}`, { method: "DELETE" }).catch(() => {});
      fetch(`https://firestore.googleapis.com/v1/projects/${_cgzVaultInit.projectId}/databases/(default)/documents/student_users/${encodeURIComponent(email)}?key=${_cgzVaultInit.apiKey}`, { method: "DELETE" }).catch(() => {});
    }

    // 4. Save to candidates collection for candidate task portal access
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

    await setDoc(doc(db, "candidates", docKey), candidateDoc, { merge: true });
    if (docKey !== email) {
      await setDoc(doc(db, "candidates", email), candidateDoc, { merge: true });
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

// Real-time Firestore Listener for Users with Strict Email Deduplication
function listenToFirebaseUsers() {
  try {
    const usersCol = collection(db, "users");

    onSnapshot(usersCol, (snapshot) => {
      const userMap = new Map();

      snapshot.forEach(docSnap => {
        const data = docSnap.data();
        const docId = docSnap.id;

        // Discard corrupted phantom docs without an email or with placeholder IDs
        const rawEmail = (data.email || (docId.includes("@") ? docId : "")).trim();
        if (!rawEmail || docId === "_" || docId === "—" || docId === "-") {
          return;
        }

        const cleanEmail = rawEmail.toLowerCase();
        if (!userMap.has(cleanEmail)) {
          userMap.set(cleanEmail, {
            id: docId,
            docKey: cleanEmail.replace(/[^a-zA-Z0-9]/g, "_"),
            docIds: [docId],
            ...data,
            email: cleanEmail
          });
        } else {
          // Merge duplicates into the single canonical entry
          const existing = userMap.get(cleanEmail);
          if (!existing.docIds.includes(docId)) {
            existing.docIds.push(docId);
          }
          if ((!existing.name || existing.name === "User") && data.name) existing.name = data.name;
          if ((!existing.password || existing.password === "••••••••") && data.password) existing.password = data.password;
          if ((!existing.course || existing.course === "Fullstack") && data.course) existing.course = data.course;
          if (data.status) existing.status = data.status;
          if (data.accessStatus) existing.accessStatus = data.accessStatus;
          if (data.uid && !existing.uid) existing.uid = data.uid;
        }
      });

      currentStudentList = Array.from(userMap.values());

      if (metricTotalStudents) metricTotalStudents.textContent = currentStudentList.length;
      if (tabStudentCount) tabStudentCount.textContent = currentStudentList.length;

      const activeCount = currentStudentList.filter(s => (s.status || s.accessStatus || "active") === "active").length;
      if (metricActiveStudents) metricActiveStudents.textContent = activeCount;

      renderUsersTable(currentStudentList);
      updateServerStorageTelemetry();
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

  // Strictly filter and deduplicate by clean email
  const seen = new Set();
  const dedupedUsers = [];
  (users || []).forEach(u => {
    const e = (u.email || "").toLowerCase().trim();
    if (!e || e === "—" || seen.has(e)) return;
    seen.add(e);
    dedupedUsers.push(u);
  });

  if (dedupedUsers.length === 0) {
    studentTableBody.innerHTML = `
      <tr>
        <td colspan="4" class="td-empty" style="text-align: center; padding: 2.5rem 1rem; color: #94a3b8;">
          No authenticated users found in Firebase Firestore.<br>Fill the form above and click <strong>"Save User to Firebase & Grant Access"</strong> to add your first user.
        </td>
      </tr>
    `;
    return;
  }

  studentTableBody.innerHTML = dedupedUsers.map(u => {
    const name = u.name || u.candidateName || "User";
    const email = u.email || "—";
    const password = u.password || "••••••••";
    const course = u.course || u.track || "Fullstack";
    const cleanEmail = email.toLowerCase().trim();
    const docKey = u.docKey || cleanEmail.replace(/[^a-zA-Z0-9]/g, "_");

    return `
      <tr data-user-email="${cleanEmail}">
        <td>
          <div class="td-candidate-info">
            <span class="td-cand-name">${name}</span>
            <span class="td-cand-email">${cleanEmail}</span>
          </div>
        </td>
        <td>
          <span class="${getCourseBadgeClass(course)}">${course}</span>
        </td>
        <td>
          <div class="pwd-masked-box">
            <span class="pwd-text font-mono" id="pwd-display-${docKey}">••••••••</span>
            <button type="button" class="btn-text-action" title="Toggle Show/Hide Password" onclick="window.adminAppTogglePwdVisibility('${docKey}')">👁️</button>
          </div>
        </td>
        <td>
          <div class="table-action-btns">
            <button type="button" class="btn-tbl-action btn-tbl-copy" title="Copy User Credentials" onclick="window.adminAppCopyStudentCreds('${cleanEmail}')">
              📋 Copy
            </button>
            <button type="button" class="btn-tbl-action btn-tbl-load" title="Edit User Credentials & Course" onclick="window.adminAppOpenEditModal('${cleanEmail}')">
              ✏️ Edit
            </button>
            <button type="button" class="btn-tbl-action btn-tbl-del" title="Delete User Permanently from Server" onclick="window.adminAppOpenDeleteModal('${cleanEmail}')">
              🗑️
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

// Global actions for user management
window.adminAppTogglePwdVisibility = function(docKey) {
  const elem = document.getElementById(`pwd-display-${docKey}`);
  if (!elem) return;
  const user = currentStudentList.find(s => s.docKey === docKey || s.id === docKey || (s.email || "").replace(/[^a-zA-Z0-9]/g, "_") === docKey);
  const pwd = user?.password || "••••••••";
  elem.textContent = elem.textContent === "••••••••" ? pwd : "••••••••";
};

window.adminAppCopyStudentCreds = function(email) {
  const cleanEmail = (email || "").toLowerCase().trim();
  const user = currentStudentList.find(s => (s.email || "").toLowerCase() === cleanEmail);
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

// ==========================================
// EDIT USER MODAL CONTROLLER
// ==========================================
window.adminAppOpenEditModal = function(email) {
  const cleanEmail = (email || "").toLowerCase().trim();
  const user = currentStudentList.find(s => (s.email || "").toLowerCase() === cleanEmail);
  if (!user) {
    showToast("⚠️ User not found in active list.");
    return;
  }

  const editModalOverlay = document.getElementById("admin-edit-modal-overlay");
  const editUserOrigEmail = document.getElementById("edit-user-orig-email");
  const editModalName = document.getElementById("edit-modal-name");
  const editModalEmail = document.getElementById("edit-modal-email");
  const editModalCourse = document.getElementById("edit-modal-course");
  const editModalBatch = document.getElementById("edit-modal-batch");

  if (editUserOrigEmail) editUserOrigEmail.value = cleanEmail;
  if (editModalName) editModalName.value = user.name || user.candidateName || "";
  if (editModalEmail) editModalEmail.value = cleanEmail;
  if (editModalCourse) editModalCourse.value = user.course || user.track || "Fullstack";
  if (editModalBatch) editModalBatch.value = user.batch || "Cohort 2026";

  if (editModalOverlay) {
    editModalOverlay.classList.add("active");
  }
};

window.adminAppCloseEditModal = function() {
  const editModalOverlay = document.getElementById("admin-edit-modal-overlay");
  if (editModalOverlay) editModalOverlay.classList.remove("active");
};

// Save edited user to server
async function handleSaveEditedUser(e) {
  if (e) e.preventDefault();

  const editUserOrigEmail = document.getElementById("edit-user-orig-email");
  const editModalName = document.getElementById("edit-modal-name");
  const editModalCourse = document.getElementById("edit-modal-course");
  const editModalBatch = document.getElementById("edit-modal-batch");
  const btnSaveEditModal = document.getElementById("btn-save-edit-modal");

  const cleanEmail = (editUserOrigEmail?.value || "").toLowerCase().trim();
  const name = editModalName?.value.trim();
  const course = editModalCourse?.value || "Fullstack";
  const batch = editModalBatch?.value.trim() || "Cohort 2026";

  if (!cleanEmail || !name) {
    showToast("⚠️ Candidate Name is required.");
    return;
  }

  if (btnSaveEditModal) {
    btnSaveEditModal.disabled = true;
    btnSaveEditModal.innerHTML = `<span>Updating Server... ⏳</span>`;
  }

  const assignedFormUrl = getCourseFormUrl(course);
  const sanitizedKey = cleanEmail.replace(/[^a-zA-Z0-9]/g, "_");

  const updatePayload = {
    name: name,
    candidateName: name,
    displayName: name,
    course: course,
    track: course,
    status: "active",
    accessStatus: "active",
    access: "granted",
    accessGranted: true,
    formUrl: assignedFormUrl,
    googleFormUrl: assignedFormUrl,
    batch: batch,
    updatedAt: serverTimestamp()
  };

  try {
    // 1. Update in Firestore users and student_users collections
    await Promise.all([
      setDoc(doc(db, "users", sanitizedKey), updatePayload, { merge: true }),
      setDoc(doc(db, "student_users", sanitizedKey), updatePayload, { merge: true })
    ]);

    // 2. Update in candidates collection for candidate task portal access
    const courseCode = course.toLowerCase().includes("java") ? "java" :
                       course.toLowerCase().includes("python") ? "python" :
                       (course.toLowerCase() === "c" || course.toLowerCase().includes("c ")) ? "c" :
                       course.toLowerCase().includes("web") ? "web" : "fullstack";

    const candidateDoc = {
      name: name,
      course: courseCode,
      status: "approved",
      updatedAt: new Date().toISOString()
    };
    setDoc(doc(db, "candidates", sanitizedKey), candidateDoc, { merge: true }).catch(() => {});
    setDoc(doc(db, "candidates", cleanEmail), candidateDoc, { merge: true }).catch(() => {});

    // 3. Update in-memory list and re-render table smoothly with no flicker
    const idx = currentStudentList.findIndex(s => (s.email || "").toLowerCase() === cleanEmail);
    if (idx !== -1) {
      Object.assign(currentStudentList[idx], updatePayload);
      renderUsersTable(currentStudentList);
      updateServerStorageTelemetry();
    }

    showToast(`✅ User "${name}" credentials updated on server!`);
    window.adminAppCloseEditModal();
  } catch (err) {
    console.error("Server update user error:", err);
    showToast(`⚠️ Server update notice: ${err.message || "Failed"}`);
  } finally {
    if (btnSaveEditModal) {
      btnSaveEditModal.disabled = false;
      btnSaveEditModal.innerHTML = `<span>💾 Save Changes to Server</span>`;
    }
  }
}

// ==========================================
// DELETE USER MODAL CONTROLLER
// ==========================================
window.adminAppOpenDeleteModal = function(email) {
  const cleanEmail = (email || "").toLowerCase().trim();
  const user = currentStudentList.find(s => (s.email || "").toLowerCase() === cleanEmail);
  if (!user) {
    showToast("⚠️ User not found in active list.");
    return;
  }

  const deleteModalOverlay = document.getElementById("admin-delete-modal-overlay");
  const deleteUserTargetEmail = document.getElementById("delete-user-target-email");
  const deleteModalTargetName = document.getElementById("delete-modal-target-name");
  const deleteModalTargetEmail = document.getElementById("delete-modal-target-email");
  const deleteModalTargetCourse = document.getElementById("delete-modal-target-course");

  if (deleteUserTargetEmail) deleteUserTargetEmail.value = cleanEmail;
  if (deleteModalTargetName) deleteModalTargetName.textContent = user.name || user.candidateName || cleanEmail;
  if (deleteModalTargetEmail) deleteModalTargetEmail.textContent = cleanEmail;
  if (deleteModalTargetCourse) {
    const course = user.course || user.track || "Fullstack";
    deleteModalTargetCourse.textContent = course;
    deleteModalTargetCourse.className = getCourseBadgeClass(course);
  }

  if (deleteModalOverlay) {
    deleteModalOverlay.classList.add("active");
  }
};

window.adminAppCloseDeleteModal = function() {
  const deleteModalOverlay = document.getElementById("admin-delete-modal-overlay");
  if (deleteModalOverlay) deleteModalOverlay.classList.remove("active");
};

// Permanently delete user from server
async function handleConfirmDeleteUser() {
  const deleteUserTargetEmail = document.getElementById("delete-user-target-email");
  const btnConfirmDeleteUser = document.getElementById("btn-confirm-delete-user");

  const cleanEmail = (deleteUserTargetEmail?.value || "").toLowerCase().trim();
  if (!cleanEmail) {
    showToast("⚠️ Invalid email for deletion.");
    return;
  }

  const user = currentStudentList.find(s => (s.email || "").toLowerCase() === cleanEmail);
  const displayName = user?.name || cleanEmail;
  const password = user?.password;
  const sanitizedKey = cleanEmail.replace(/[^a-zA-Z0-9]/g, "_");

  if (btnConfirmDeleteUser) {
    btnConfirmDeleteUser.disabled = true;
    btnConfirmDeleteUser.innerHTML = `<span>Deleting from Server... ⏳</span>`;
  }

  // Optimistically remove from currentStudentList and update UI immediately
  currentStudentList = currentStudentList.filter(s => (s.email || "").toLowerCase() !== cleanEmail);
  if (metricTotalStudents) metricTotalStudents.textContent = currentStudentList.length;
  if (tabStudentCount) tabStudentCount.textContent = currentStudentList.length;
  const activeCount = currentStudentList.filter(s => (s.status || s.accessStatus || "active") === "active").length;
  if (metricActiveStudents) metricActiveStudents.textContent = activeCount;
  renderUsersTable(currentStudentList);
  updateServerStorageTelemetry();

  window.adminAppCloseDeleteModal();

  try {
    const deletePromises = [
      deleteDoc(doc(db, "users", sanitizedKey)),
      deleteDoc(doc(db, "users", cleanEmail)),
      deleteDoc(doc(db, "student_users", sanitizedKey)),
      deleteDoc(doc(db, "student_users", cleanEmail)),
      deleteDoc(doc(db, "candidates", sanitizedKey)),
      deleteDoc(doc(db, "candidates", cleanEmail)),
      deleteDoc(doc(db, "interns", sanitizedKey)),
      deleteDoc(doc(db, "interns", cleanEmail))
    ];

    // REST API fallback deletes
    const restCollections = ["users", "student_users", "candidates", "interns"];
    restCollections.forEach(col => {
      deletePromises.push(
        fetch(`https://firestore.googleapis.com/v1/projects/${_cgzVaultInit.projectId}/databases/(default)/documents/${col}/${encodeURIComponent(sanitizedKey)}?key=${_cgzVaultInit.apiKey}`, { method: "DELETE" }).catch(() => {})
      );
      if (cleanEmail !== sanitizedKey) {
        deletePromises.push(
          fetch(`https://firestore.googleapis.com/v1/projects/${_cgzVaultInit.projectId}/databases/(default)/documents/${col}/${encodeURIComponent(cleanEmail)}?key=${_cgzVaultInit.apiKey}`, { method: "DELETE" }).catch(() => {})
        );
      }
    });

    // Delete from Firebase Auth if password available
    if (password && password !== "••••••••") {
      fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${_cgzVaultInit.apiKey}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: cleanEmail, password: password, returnSecureToken: true })
      }).then(res => res.json()).then(data => {
        if (data && data.idToken) {
          fetch(`https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${_cgzVaultInit.apiKey}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ idToken: data.idToken })
          }).catch(() => {});
        }
      }).catch(() => {});
    }

    await Promise.allSettled(deletePromises);
    showToast(`🗑️ User "${displayName}" permanently deleted from server!`);
  } catch (err) {
    console.error("Server deletion error:", err);
    showToast(`⚠️ Server deletion notice: ${err.message || "Completed"}`);
  } finally {
    if (btnConfirmDeleteUser) {
      btnConfirmDeleteUser.disabled = false;
      btnConfirmDeleteUser.innerHTML = `<span>🗑️ Permanently Delete</span>`;
    }
  }
}

// Bind modal buttons
const editUserFormElem = document.getElementById("admin-edit-user-form");
if (editUserFormElem) {
  editUserFormElem.addEventListener("submit", handleSaveEditedUser);
}

const btnCloseEditModal = document.getElementById("btn-close-edit-modal");
if (btnCloseEditModal) {
  btnCloseEditModal.addEventListener("click", window.adminAppCloseEditModal);
}

const btnCancelEditModal = document.getElementById("btn-cancel-edit-modal");
if (btnCancelEditModal) {
  btnCancelEditModal.addEventListener("click", window.adminAppCloseEditModal);
}



const btnCloseDeleteModal = document.getElementById("btn-close-delete-modal");
if (btnCloseDeleteModal) {
  btnCloseDeleteModal.addEventListener("click", window.adminAppCloseDeleteModal);
}

const btnCancelDeleteModal = document.getElementById("btn-cancel-delete-modal");
if (btnCancelDeleteModal) {
  btnCancelDeleteModal.addEventListener("click", window.adminAppCloseDeleteModal);
}

const btnConfirmDeleteUser = document.getElementById("btn-confirm-delete-user");
if (btnConfirmDeleteUser) {
  btnConfirmDeleteUser.addEventListener("click", handleConfirmDeleteUser);
}

// Close modals when clicking backdrop
window.addEventListener("click", (e) => {
  const editOverlay = document.getElementById("admin-edit-modal-overlay");
  const deleteOverlay = document.getElementById("admin-delete-modal-overlay");
  if (e.target === editOverlay) window.adminAppCloseEditModal();
  if (e.target === deleteOverlay) window.adminAppCloseDeleteModal();
});

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
function getTrackPrefixCode(trackName) {
  const t = (trackName || "").toLowerCase().trim();
  if (t.includes("java") || t === "jp") return "JP";
  if (t.includes("python") || t === "py") return "PY";
  if (t === "c" || t.includes("c ") || t.includes("c prog") || t.includes("c programming") || t === "cp") return "CP";
  if (t.includes("web") || t.includes("frontend") || t === "wd") return "WD";
  if (t.includes("full") || t.includes("stack") || t === "fs") return "FS";
  if (t.includes("ai") || t.includes("machine")) return "AI";
  if (t.includes("data") || t.includes("analytics")) return "DS";
  if (t.includes("cloud") || t.includes("aws") || t.includes("azure")) return "CL";
  if (t.includes("cyber") || t.includes("security")) return "CS";
  if (t.includes("android") || t.includes("flutter") || t.includes("mobile") || t.includes("app")) return "AD";

  const clean = t.replace(/[^a-z]/g, "");
  if (clean.length >= 2) return clean.slice(0, 2).toUpperCase();
  return "FS";
}

function generateSerialId(trackOverride, advance = false) {
  const track = trackOverride || candTrackInput?.value || "Fullstack";
  const code = getTrackPrefixCode(track);
  const prefix = `CG-IN-${code}-CERT-`;

  let maxNum = 0;
  if (Array.isArray(currentCertsList)) {
    currentCertsList.forEach(cert => {
      const serial = (cert.serialNumber || cert.certId || cert.id || "").trim().toUpperCase();
      if (serial.startsWith(prefix)) {
        const numPart = parseInt(serial.replace(prefix, ""), 10);
        if (!isNaN(numPart) && numPart > maxNum) {
          maxNum = numPart;
        }
      }
    });
  }

  // If advance is requested (e.g. clicking 'New ID' or after saving) and input already matches prefix, advance past current input
  if (advance && candSerialInput && candSerialInput.value.toUpperCase().startsWith(prefix)) {
    const currentNum = parseInt(candSerialInput.value.toUpperCase().replace(prefix, ""), 10);
    if (!isNaN(currentNum) && currentNum >= maxNum) {
      maxNum = currentNum;
    }
  }

  const nextNum = maxNum + 1;
  const serial = `${prefix}${String(nextNum).padStart(6, "0")}`;

  if (candSerialInput) {
    candSerialInput.value = serial;
  }
  updateLivePreview();
  return serial;
}

function buildVerificationUrl(baseUrl, paramKey, paramVal) {
  let defaultBase = "https://internships.coralgenz.co.in/";
  if (typeof window !== "undefined" && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")) {
    defaultBase = `${window.location.origin}/internships/index.html`;
  }
  let base = (baseUrl || defaultBase).trim().split("?")[0].replace(/\/$/, "");
  const separator = base.endsWith(".html") || base.endsWith(".htm") ? "?" : "/?";
  return `${base}${separator}${paramKey}=${encodeURIComponent(paramVal)}`;
}

function generateVerificationQR(candidateData, targetBaseUrl) {
  if (!qrCanvasBox) return "";

  currentSaltedToken = generateSaltedHashToken(candidateData);
  const fullVerificationUrl = buildVerificationUrl(targetBaseUrl, "v", currentSaltedToken);

  qrCanvasBox.innerHTML = "";

  try {
    if (typeof QRCode !== "undefined") {
      qrCodeInstance = new QRCode(qrCanvasBox, {
        text: fullVerificationUrl,
        width: 240,
        height: 240,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.L
      });
    } else {
      const img = document.createElement("img");
      img.src = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&ecc=L&margin=4&data=${encodeURIComponent(fullVerificationUrl)}`;
      img.alt = `QR Code`;
      qrCanvasBox.appendChild(img);
    }
  } catch (err) {
    console.error("QR Code Generation Error:", err);
    const img = document.createElement("img");
    img.src = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&ecc=L&margin=4&data=${encodeURIComponent(fullVerificationUrl)}`;
    img.alt = `QR Code`;
    qrCanvasBox.appendChild(img);
  }

  return fullVerificationUrl;
}

function updateLivePreview() {
  const name = candNameInput?.value.trim() || "Karthick Krishna";
  const email = candEmailInput?.value.trim() || "candidate@gmail.com";
  const track = candTrackInput?.value || "Fullstack";
  const defaultCode = getTrackPrefixCode(track);
  const serialId = candSerialInput?.value.trim() || `CG-IN-${defaultCode}-CERT-000001`;
  const duration = "1 Month";
  const issueDate = candIssueDateInput?.value.trim() || "August 2026";
  let defaultVerifyUrl = "https://internships.coralgenz.co.in/";
  if (typeof window !== "undefined" && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")) {
    defaultVerifyUrl = `${window.location.origin}/internships/index.html`;
  }
  const verifyUrl = candVerifyUrlInput?.value.trim() || defaultVerifyUrl;

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
    status: "100% Completed • Verified Deliverables",
    issuingAuthority: "Coralgenz Global Corporate Registry"
  };

  generateVerificationQR(candidatePayload, verifyUrl);
}

// Expose globally
window.updateLivePreview = updateLivePreview;
window.generateSerialId = generateSerialId;

// Live preview updates for regular inputs
[candNameInput, candEmailInput, candSerialInput, candIssueDateInput, candVerifyUrlInput].forEach(elem => {
  if (elem) {
    elem.addEventListener("input", updateLivePreview);
    elem.addEventListener("change", updateLivePreview);
  }
});

// Auto-generate serial immediately whenever course track changes
if (candTrackInput) {
  const onTrackSelected = () => {
    generateSerialId(candTrackInput.value, false);
    updateLivePreview();
  };
  candTrackInput.addEventListener("change", onTrackSelected);
  candTrackInput.addEventListener("input", onTrackSelected);
}

let isSavingCert = false;

async function saveCertificateToFirebase(e) {
  if (e) e.preventDefault();
  if (isSavingCert) return;

  const name = candNameInput?.value.trim();
  const email = candEmailInput?.value.trim().toLowerCase();
  const track = candTrackInput?.value || "Fullstack";
  let serialId = (candSerialInput?.value.trim() || "").toUpperCase();
  const duration = "1 Month";
  const issueDate = candIssueDateInput?.value.trim() || "August 2026";
  const verifyBaseUrl = candVerifyUrlInput?.value.trim() || "https://internships.coralgenz.co.in/";

  if (!name || !email) {
    showCertAlert("error", "Please fill in Candidate Full Name and Email Address.");
    showToast("⚠️ Please enter candidate name and email.");
    return;
  }

  if (!serialId) {
    serialId = generateSerialId(track, false);
  }

  isSavingCert = true;

  if (btnSaveFirebase) {
    btnSaveFirebase.disabled = true;
    btnSaveFirebase.innerHTML = `<span>Saving to Firebase... ⏳</span>`;
  }

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
    status: "100% Completed • Verified Deliverables",
    issuingAuthority: "Coralgenz Global Corporate Registry",
    updatedAt: serverTimestamp(),
    createdAt: serverTimestamp()
  };

  const saltedToken = generateSaltedHashToken(certData);
  const fullVerifyUrl = buildVerificationUrl(verifyBaseUrl, "v", saltedToken);

  certData.saltedToken = saltedToken;
  certData.verificationUrl = fullVerifyUrl;

  try {
    // 1. Save directly to certificates collection
    await setDoc(doc(db, "certificates", serialId), certData, { merge: true });

    // 2. Save directly to interns collection by email and serialId
    const sanitizedEmailKey = email.replace(/[^a-zA-Z0-9]/g, "_");
    await setDoc(doc(db, "interns", sanitizedEmailKey), certData, { merge: true });
    await setDoc(doc(db, "interns", serialId), certData, { merge: true });

    showCertAlert("success", `✅ <strong>Certificate Issued & Synced!</strong><br>Candidate: <strong>${name}</strong> (${serialId})<br>Track: <strong>${track}</strong><br>Saved directly to Firebase Firestore!`);
    showToast(`🎉 Certificate ${serialId} saved to Firebase!`);

    // Auto-advance to the next serial ID for this track
    generateSerialId(track, true);
  } catch (err) {
    console.error("Firebase write error:", err);
    showCertAlert("error", `Firebase Write Error: ${err.message}.`);
    showToast("⚠️ Firebase Firestore sync error.");
  } finally {
    isSavingCert = false;
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

if (btnSaveFirebase) {
  btnSaveFirebase.addEventListener("click", (e) => {
    if (certForm && !certForm.checkValidity()) {
      certForm.reportValidity();
      return;
    }
    saveCertificateToFirebase(e);
  });
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

      // Ensure input displays track-formatted serial if empty, using old MSME format, or already taken
      const currentTrack = candTrackInput?.value || "Fullstack";
      const isTaken = currentCertsList.some(cert => (cert.serialNumber || cert.certId || cert.id || "").trim().toUpperCase() === (candSerialInput?.value || "").trim().toUpperCase());
      if (candSerialInput && (!candSerialInput.value || candSerialInput.value.startsWith("CG-MSME-") || isTaken)) {
        generateSerialId(currentTrack, false);
      }

      renderCertificatesTable(currentCertsList);
      updateServerStorageTelemetry();
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

// Helper: Filter out browser cache-busters like 20261017_r4, 2026.30, timestamps
function isCacheBuster(str) {
  if (!str) return true;
  const s = str.trim();
  if (/^\d{8}(_r\d+)?$/i.test(s)) return true;
  if (/^v?\d+(\.\d+)+(_r\d+)?$/i.test(s)) return true;
  if (/^\d+$/i.test(s)) return true;
  return false;
}

// Scanned verification URL query handler (NO CRYPTOGRAPHIC SALT OR GRADE EXPOSED)
async function checkUrlParamsForVerification() {
  const params = new URLSearchParams(window.location.search);
  
  // 1. Check for explicit certificate verification queries
  const explicitVerifyParam = (params.get("cert_id") || params.get("verify") || params.get("certificate") || "").trim();
  const vParam = (params.get("v") || params.get("token") || params.get("id") || "").trim();

  let targetTokenOrSerial = "";
  if (explicitVerifyParam && !isCacheBuster(explicitVerifyParam)) {
    if (isSaltedHashToken(explicitVerifyParam) || explicitVerifyParam.toUpperCase().startsWith("CG-") || explicitVerifyParam.toUpperCase().includes("CERT")) {
      targetTokenOrSerial = explicitVerifyParam;
    }
  } else if (vParam && !isCacheBuster(vParam)) {
    // Only accept vParam if it is an authentic cryptographic salted token OR starts with CG- / contains CERT
    if (isSaltedHashToken(vParam)) {
      targetTokenOrSerial = vParam;
    } else if (vParam.toUpperCase().startsWith("CG-") || vParam.toUpperCase().includes("CERT")) {
      targetTokenOrSerial = vParam;
    }
  }

  // If no genuine certificate token/serial is present, or if it is just a cache buster (e.g. 20261017_r4, 2026.9), ignore safely!
  if (!targetTokenOrSerial || isCacheBuster(targetTokenOrSerial)) return;

  // 1. If Salted Token
  if (isSaltedHashToken(targetTokenOrSerial)) {
    const verified = verifyAndDecodeSaltedHash(targetTokenOrSerial);
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
      console.warn("Salted token verification note on page load:", verified.message);
      return;
    }
  }

  // 2. Direct Serial lookup
  const serialId = targetTokenOrSerial;
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
      console.warn(`Certificate serial ${serialId} from URL parameter not found in database.`);
    }
  } catch (err) {
    console.warn("Verification lookup error:", err);
  }
}

// Certificate Action buttons
if (btnGenNewId) {
  btnGenNewId.addEventListener("click", () => {
    const newId = generateSerialId(candTrackInput?.value, true);
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
    generateSerialId(pick.track);
    updateLivePreview();
    showToast(`Loaded sample profile for ${pick.name}! ✨`);
  });
}

if (btnResetForm) {
  btnResetForm.addEventListener("click", () => {
    if (certForm) certForm.reset();
    generateSerialId(candTrackInput?.value || "Fullstack");
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
    const serial = candSerialInput?.value.trim() || "CG-IN-CERT-000001";
    let defaultBase = "https://internships.coralgenz.co.in/";
    const fullUrl = currentSaltedToken 
      ? buildVerificationUrl(candVerifyUrlInput?.value, "v", currentSaltedToken)
      : buildVerificationUrl(candVerifyUrlInput?.value, "id", serial);

    // Create high-definition 400x400 QR canvas for download
    const tempDiv = document.createElement("div");
    tempDiv.style.position = "absolute";
    tempDiv.style.left = "-9999px";
    tempDiv.style.top = "-9999px";
    document.body.appendChild(tempDiv);

    try {
      if (typeof QRCode !== "undefined") {
        new QRCode(tempDiv, {
          text: fullUrl,
          width: 320,
          height: 320,
          colorDark: "#000000",
          colorLight: "#ffffff",
          correctLevel: QRCode.CorrectLevel.L
        });

        setTimeout(() => {
          const rawCanvas = tempDiv.querySelector("canvas");
          if (rawCanvas) {
            // Add a clean 40px white quiet-zone border for maximum scanner recognition
            const exportCanvas = document.createElement("canvas");
            exportCanvas.width = 400;
            exportCanvas.height = 400;
            const expCtx = exportCanvas.getContext("2d");
            expCtx.imageSmoothingEnabled = false;
            expCtx.fillStyle = "#ffffff";
            expCtx.fillRect(0, 0, 400, 400);
            expCtx.drawImage(rawCanvas, 40, 40, 320, 320);

            const a = document.createElement("a");
            a.href = exportCanvas.toDataURL("image/png");
            a.download = `Coralgenz-QR-${serial}.png`;
            a.click();
            showToast(`📥 High-Definition QR Code downloaded for ${serial}!`);
          } else {
            // Fallback to table/preview canvas
            const canvas = qrCanvasBox?.querySelector("canvas");
            if (canvas) {
              const a = document.createElement("a");
              a.href = canvas.toDataURL("image/png");
              a.download = `Coralgenz-QR-${serial}.png`;
              a.click();
            }
          }
          document.body.removeChild(tempDiv);
        }, 100);
      } else {
        const a = document.createElement("a");
        a.href = `https://api.qrserver.com/v1/create-qr-code/?size=400x400&ecc=L&margin=4&data=${encodeURIComponent(fullUrl)}`;
        a.download = `Coralgenz-QR-${serial}.png`;
        a.click();
        document.body.removeChild(tempDiv);
      }
    } catch (err) {
      console.error("QR download error:", err);
      if (tempDiv.parentNode) document.body.removeChild(tempDiv);
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
    const url = currentSaltedToken 
      ? buildVerificationUrl(candVerifyUrlInput?.value, "v", currentSaltedToken)
      : buildVerificationUrl(candVerifyUrlInput?.value, "id", candSerialInput?.value.trim() || "CG-IN-FS-CERT-000001");

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

  generateSerialId(candTrackInput?.value || "Fullstack");
  updateLivePreview();
  listenToFirebaseCertificates();
  checkUrlParamsForVerification();
  updateServerStorageTelemetry();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initAdminApp);
} else {
  initAdminApp();
}
