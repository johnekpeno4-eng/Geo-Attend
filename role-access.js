(function () {
  const savedTheme = localStorage.getItem("geoAttendTheme") || "light";
  document.documentElement.classList.toggle("dark", savedTheme === "dark");
  document.documentElement.classList.toggle("light", savedTheme !== "dark");

  const ADMIN_PAGES = new Set(["dashboard.html", "create-session.html", "live-monitor.html", "students.html", "records.html", "session-report.html", "admin-management.html", "courses.html"]);
  const STUDENT_PAGES = new Set(["student-home.html", "student-history.html", "student-profile.html", "identity-verification.html"]);
  const PUBLIC_PAGES = new Set(["login.html", "register.html", ""]);

  const page = window.location.pathname.split("/").pop();
  const role = localStorage.getItem("geoAttendRole");
  const currentUserEmail = localStorage.getItem("geoAttendCurrentUser");
  const adminEmail = localStorage.getItem("geoAttendAdminEmail");
  const isAdminPage = ADMIN_PAGES.has(page);
  const isStudentPage = STUDENT_PAGES.has(page);
  const isPublicPage = PUBLIC_PAGES.has(page);

  syncRegistrationReset();

  function go(target) {
    if (page !== target) window.location.replace(target);
  }

  function getAccounts() {
    return JSON.parse(localStorage.getItem("geoAttendAccounts") || "[]");
  }

  function saveAccounts(accounts) {
    localStorage.setItem("geoAttendAccounts", JSON.stringify(accounts));
  }
  async function syncRegistrationReset() {
    try {
      const response = await fetch("/api/registration-reset", { cache: "no-store" });
      if (!response.ok) return;
      const reset = await response.json();
      const version = String(reset.version || "");
      if (!version || localStorage.getItem("geoAttendRegistrationResetVersion") === version) return;
      const currentRole = localStorage.getItem("geoAttendRole");
      localStorage.removeItem("geoAttendAccounts");
      localStorage.removeItem("geoAttendBiometricProfiles");
      Object.keys(localStorage).forEach((key) => {
        if (key.startsWith("geoAttendStudentSettings:")) localStorage.removeItem(key);
      });
      localStorage.setItem("geoAttendRegistrationResetVersion", version);
      if (currentRole === "student") {
        localStorage.removeItem("geoAttendCurrentUser");
        localStorage.removeItem("geoAttendRole");
        localStorage.removeItem("geoAttendView");
      }
    } catch {
      // Keep the page usable if the backend is briefly unavailable.
    }
  }

  const currentAccount = getAccounts().find((account) => account.email === currentUserEmail && account.verified);
  const isAdminSession = role === "admin" && currentUserEmail && adminEmail && currentUserEmail === adminEmail;


  function studentIdentityComplete(email, account) {
    if (!email) return false;
    const profiles = JSON.parse(localStorage.getItem("geoAttendBiometricProfiles") || "{}");
    const profile = profiles[email];
    return Boolean(profile?.webauthnCredential?.id && profile?.identityVerified === true);
  }
  function firstTwoNames(value) {
    const text = String(value || "").trim();
    if (!text) return "";
    return text.split(/\s+/).filter(Boolean).slice(0, 2).join(" ");
  }

  function getDisplayAccount() {
    const accounts = getAccounts();
    return accounts.find((account) => account.email === currentUserEmail)
      || accounts.find((account) => account.email === adminEmail)
      || currentAccount
      || null;
  }

  function getDisplayName() {
    const adminName = firstTwoNames(localStorage.getItem("geoAttendAdminName"));
    if (role === "admin" && adminName) return adminName;
    const accountName = firstTwoNames(getDisplayAccount()?.fullName);
    if (accountName) return accountName;
    const emailName = firstTwoNames(String(currentUserEmail || "").split("@")[0].replace(/[._-]+/g, " "));
    if (emailName) return emailName;
    return role === "admin" ? "Admin User" : "Student";
  }

  if (!isPublicPage && !currentAccount && !isAdminSession) {
    localStorage.removeItem("geoAttendRole");
    localStorage.removeItem("geoAttendView");
    localStorage.removeItem("geoAttendCurrentUser");
    localStorage.removeItem("geoAttendAdminEmail");
    go("login.html");
    return;
  }


  if (role === "student" && isStudentPage && page !== "identity-verification.html" && !studentIdentityComplete(currentUserEmail, currentAccount)) {
    go("identity-verification.html");
    return;
  }
  if (!role && !isPublicPage) {
    go("login.html");
    return;
  }

  if (role === "student" && isAdminPage) {
    go("student-home.html");
    return;
  }

  const adminRole = localStorage.getItem("geoAttendAdminRole") || "";
  const lecturerRestrictedPages = new Set(["admin-management.html", "courses.html", "students.html", "records.html"]);
  if (role === "admin" && adminRole === "lecturer_admin" && lecturerRestrictedPages.has(page)) {
    go("dashboard.html");
    return;
  }
  if (role === "admin" && isStudentPage) {
    localStorage.setItem("geoAttendView", "student");
  }

  if (role === "admin" && isAdminPage) {
    localStorage.setItem("geoAttendView", "admin");
  }

  document.addEventListener("DOMContentLoaded", () => {
    updateHeaderIdentity();

    if (role === "student" && page === "student-checkin.html") {
      const currentUser = localStorage.getItem("geoAttendCurrentUser");
      const profiles = JSON.parse(localStorage.getItem("geoAttendBiometricProfiles") || "{}");
      if (currentUser && !profiles[currentUser]) {
        window.location.replace("identity-verification.html");
        return;
      }
      window.location.replace("student-home.html#active-classes");
      return;
    }

    const loginForm = document.querySelector("[data-login-form]");
    if (loginForm) {
      loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const formData = new FormData(loginForm);
        const email = (formData.get("email") || "").trim().toLowerCase();
        const password = formData.get("password") || "";

        const message = document.getElementById("login-message");

        async function finishStudentLogin(user, successText = "Login successful. Redirecting...") {
          const accounts = getAccounts();
          const existing = accounts.find((savedAccount) => savedAccount.email === user.email);
          if (existing) Object.assign(existing, user, { verified: true });
          else accounts.push({ ...user, verified: true, role: user.role || "student" });
          saveAccounts(accounts);
          const role = user.role || "student";
          localStorage.setItem("geoAttendCurrentUser", user.email);
          localStorage.setItem("geoAttendRole", role);
          localStorage.setItem("geoAttendView", role === "admin" ? "admin" : "student");
          localStorage.removeItem("geoAttendAdminEmail");
          localStorage.removeItem("geoAttendAdminRole");
          localStorage.removeItem("geoAttendAdminName");
          localStorage.removeItem("geoAttendAdminFacultyId");
          localStorage.removeItem("geoAttendAdminFacultyName");
          localStorage.removeItem("geoAttendAdminDepartmentId");
          localStorage.removeItem("geoAttendAdminDepartmentName");
          localStorage.removeItem("geoAttendAdminLevelId");
          localStorage.removeItem("geoAttendAdminLevelName");
          if (message) {
            message.textContent = successText;
            message.classList.remove("hidden");
            message.classList.remove("text-[#93000a]", "bg-[#ffdad6]");
            message.classList.add("text-[#0058be]", "bg-[#eff4ff]");
          }
          setTimeout(() => {
            window.location.href = role === "admin" ? "dashboard.html" : "student-home.html";
          }, 500);
        }


        async function loginStudentFromServer() {
          const result = await postJson("/api/student-login", { email, password });
          await finishStudentLogin(result.user || result, "Student login successful. Redirecting...");
        }

        try {
          const adminResult = await postJson("/api/admin-login", { email, password });
          localStorage.setItem("geoAttendCurrentUser", adminResult.user.email);
          localStorage.setItem("geoAttendAdminEmail", adminResult.user.email);
          localStorage.setItem("geoAttendAdminRole", adminResult.user.adminRole || "admin");
          localStorage.setItem("geoAttendAdminName", adminResult.user.fullName || "");
          localStorage.setItem("geoAttendAdminFacultyId", adminResult.user.facultyId || "");
          localStorage.setItem("geoAttendAdminFacultyName", adminResult.user.facultyName || "");
          localStorage.setItem("geoAttendAdminDepartmentId", adminResult.user.departmentId || "");
          localStorage.setItem("geoAttendAdminDepartmentName", adminResult.user.departmentName || "");
          localStorage.setItem("geoAttendAdminLevelId", adminResult.user.levelId || "");
          localStorage.setItem("geoAttendAdminLevelName", adminResult.user.levelName || "");
          localStorage.setItem("geoAttendRole", "admin");
          localStorage.setItem("geoAttendView", "admin");
          sessionStorage.removeItem("geoAttendAdminAuditSent");

          if (message) {
            message.textContent = "Admin login successful. Opening dashboard...";
            message.classList.remove("hidden");
            message.classList.remove("text-[#93000a]", "bg-[#ffdad6]");
            message.classList.add("text-[#0058be]", "bg-[#eff4ff]");
          }

          setTimeout(() => {
            window.location.href = "dashboard.html";
          }, 500);
          return;
        } catch (error) {
          if (error.status !== 401) {
            if (message) {
              message.textContent = error.message;
              message.classList.remove("hidden");
              message.classList.remove("text-[#0058be]", "bg-[#eff4ff]");
              message.classList.add("text-[#93000a]", "bg-[#ffdad6]");
            }
            return;
          }
        }


        const account = getAccounts().find((savedAccount) => savedAccount.email === email);
        if (!account) {
          try {
            await loginStudentFromServer();
          } catch (error) {
            if (message) {
              message.textContent = error.message || "No account found with this email. Please create an account first.";
              message.classList.remove("hidden");
              message.classList.remove("text-[#0058be]", "bg-[#eff4ff]");
              message.classList.add("text-[#93000a]", "bg-[#ffdad6]");
            }
          }
          return;
        }

        if (!account.verified) {
          if (message) {
            message.textContent = "This account has not completed OTP verification.";
            message.classList.remove("hidden");
            message.classList.remove("text-[#0058be]", "bg-[#eff4ff]");
            message.classList.add("text-[#93000a]", "bg-[#ffdad6]");
          }
          return;
        }

        if (account.password !== password) {
          try {
            await loginStudentFromServer();
          } catch (error) {
            if (message) {
              message.textContent = error.message || "Incorrect password. Please try again.";
              message.classList.remove("hidden");
              message.classList.remove("text-[#0058be]", "bg-[#eff4ff]");
              message.classList.add("text-[#93000a]", "bg-[#ffdad6]");
            }
          }
          return;
        }

        await finishStudentLogin(account);
      });
    }

    const biometricLoginButton = document.getElementById("biometric-login");
    if (biometricLoginButton) {
      const decodeBase64Url = (value) => {
        const text = String(value || "");
        const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
        const binary = atob(padded);
        return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
      };
      const encodeBase64Url = (value) => {
        const bytes = new Uint8Array(value);
        let binary = "";
        bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      };
      const prepareAuthenticationOptions = (options) => ({
        ...options,
        challenge: decodeBase64Url(options.challenge),
        allowCredentials: (options.allowCredentials || []).map((credential) => ({
          ...credential,
          id: decodeBase64Url(credential.id)
        }))
      });
      const serializeAuthenticationResponse = (credential) => ({
        id: credential.id,
        rawId: encodeBase64Url(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: encodeBase64Url(credential.response.authenticatorData),
          clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
          signature: encodeBase64Url(credential.response.signature),
          userHandle: credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : null
        }
      });
      biometricLoginButton.addEventListener("click", async () => {
        const identifier = String(document.getElementById("email")?.value || "").trim();
        const message = document.getElementById("login-message");
        const showError = (text) => {
          if (!message) return;
          message.textContent = text;
          message.classList.remove("hidden", "text-[#0058be]", "bg-[#eff4ff]");
          message.classList.add("text-[#93000a]", "bg-[#ffdad6]");
        };
        if (!identifier) {
          showError("Enter your email or registration number first.");
          document.getElementById("email")?.focus();
          return;
        }
        if (!window.isSecureContext || !navigator.credentials?.get) {
          showError("Fingerprint login requires the HTTPS GeoAttend address. Open the secure tunnel link.");
          return;
        }
        biometricLoginButton.disabled = true;
        biometricLoginButton.innerHTML = '<span class="material-symbols-outlined">fingerprint</span>Waiting for fingerprint...';
        try {
          const optionsData = await postJson("/api/webauthn/login-options", { email: identifier, purpose: "login" });
          const credential = await navigator.credentials.get({ publicKey: prepareAuthenticationOptions(optionsData.options) });
          if (!credential) throw new Error("Fingerprint login was cancelled.");
          const result = await postJson("/api/webauthn/login-verify", { email: identifier, response: serializeAuthenticationResponse(credential) });
          await finishStudentLogin(result.user, "Fingerprint login successful. Redirecting...");
        } catch (error) {
          showError(error?.name === "NotAllowedError" ? "Fingerprint login was cancelled or timed out." : (error.message || "Fingerprint login failed."));
          biometricLoginButton.disabled = false;
          biometricLoginButton.innerHTML = '<span class="material-symbols-outlined">fingerprint</span>Login with fingerprint';
        }
      });
    }
    const togglePassword = document.getElementById("toggle-password");
    const passwordInput = document.getElementById("password");

    if (togglePassword && passwordInput) {
      togglePassword.addEventListener("click", () => {
        const shouldShow = passwordInput.type === "password";
        passwordInput.type = shouldShow ? "text" : "password";
        togglePassword.querySelector(".material-symbols-outlined").textContent = shouldShow ? "visibility_off" : "visibility";
      });
    }


    document.querySelectorAll("[data-toggle-password]").forEach((button) => {
      button.addEventListener("click", () => {
        const selector = button.getAttribute("data-toggle-password");
        const input = selector ? document.querySelector(selector) : null;
        if (!input) return;
        const shouldShow = input.type === "password";
        input.type = shouldShow ? "text" : "password";
        const icon = button.querySelector(".material-symbols-outlined");
        if (icon) icon.textContent = shouldShow ? "visibility_off" : "visibility";
        button.setAttribute("aria-label", shouldShow ? "Hide password" : "Show password");
      });
    });
    function getApiTargets(url) {
      const targets = [url];
      const configuredPort = "4600";
      const shouldUseLocalBackend = window.location.protocol === "file:";
      if (shouldUseLocalBackend && url.startsWith("/")) {
        targets.push(`http://127.0.0.1:${configuredPort}${url}`);
      }
      return [...new Set(targets)];
    }

    async function postJson(url, payload) {
      let networkError = null;
      for (const target of getApiTargets(url)) {
        try {
          const response = await fetch(target, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
          const data = await response.json().catch(() => ({}));
          if (!response.ok) {
            const error = new Error(data.error || "Unable to complete request.");
            error.status = response.status;
            throw error;
          }
          return data;
        } catch (error) {
          if (error.status) throw error;
          networkError = error;
        }
      }

      const error = new Error(`Could not reach the GeoAttend backend. Open ${window.location.origin}/login.html and make sure the server is running.`);
      error.cause = networkError;
      throw error;
    }

    function captureAdminGpsForAudit() {
      return new Promise((resolve) => {
        if (!navigator.geolocation) {
          resolve({ gpsStatus: "unsupported", gps: null });
          return;
        }

        let finished = false;
        const finish = (result) => {
          if (finished) return;
          finished = true;
          window.clearTimeout(timeout);
          resolve(result);
        };
        const timeout = window.setTimeout(() => {
          finish({ gpsStatus: "timeout", gps: null });
        }, 9000);

        navigator.geolocation.getCurrentPosition((position) => {
          finish({
            gpsStatus: "captured",
            gps: {
              lat: position.coords.latitude,
              lng: position.coords.longitude,
              accuracy: Math.round(position.coords.accuracy || 0),
              capturedAt: new Date(position.timestamp || Date.now()).toISOString()
            }
          });
        }, (error) => {
          finish({
            gpsStatus: error.code === error.PERMISSION_DENIED ? "denied" : "failed",
            gps: null,
            gpsError: error.message || "Location capture failed."
          });
        }, {
          enableHighAccuracy: true,
          maximumAge: 0,
          timeout: 8000
        });
      });
    }

    async function getIpLocationForAudit() {
      try {
        const response = await fetch("https://ipapi.co/json/", { cache: "no-store" });
        if (!response.ok) return null;
        const data = await response.json();
        return {
          ip: data.ip || null,
          city: data.city || null,
          region: data.region || null,
          country: data.country_name || data.country || null,
          latitude: data.latitude || null,
          longitude: data.longitude || null,
          source: "ipapi"
        };
      } catch {
        return null;
      }
    }

    async function sendAdminLoginAudit(email) {
      if (!email || sessionStorage.getItem("geoAttendAdminAuditSent") === "true") return;
      sessionStorage.setItem("geoAttendAdminAuditSent", "true");
      const [gpsResult, ipLocation] = await Promise.all([
        captureAdminGpsForAudit(),
        getIpLocationForAudit()
      ]);

      try {
        await postJson("/api/admin-login-audit", {
          email,
          ...gpsResult,
          ipLocation,
          device: {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || ""
          }
        });
      } catch {
        sessionStorage.removeItem("geoAttendAdminAuditSent");
      }
    }

    function showLoginMessage(text, isError = false) {
      const message = document.getElementById("login-message");
      if (!message) return;
      message.textContent = text;
      message.classList.remove("hidden");
      message.classList.toggle("text-[#93000a]", isError);
      message.classList.toggle("bg-[#ffdad6]", isError);
      message.classList.toggle("text-[#0058be]", !isError);
      message.classList.toggle("bg-[#eff4ff]", !isError);
    }

    const forgotPassword = document.getElementById("forgot-password");
    if (forgotPassword) {
      const resetSection = document.getElementById("reset-password-section");
      const resetHelper = document.getElementById("reset-helper");
      const resetOtp = document.getElementById("reset-otp");
      const newPassword = document.getElementById("new-password");
      const newPasswordStep = document.getElementById("new-password-step");
      const resetButton = document.getElementById("reset-password-button");
      let resetEmail = "";
      let resetCodeVerified = false;

      forgotPassword.addEventListener("click", async (event) => {
        event.preventDefault();
        const emailInput = document.getElementById("email");
        const email = (emailInput?.value || "").trim().toLowerCase();

        if (!email) {
          showLoginMessage("Enter your registered email first, then click Forgot Password.", true);
          emailInput?.focus();
          return;
        }

        resetEmail = email;
        resetCodeVerified = false;
        newPasswordStep?.classList.add("hidden");
        if (newPassword) newPassword.value = "";
        if (resetButton) resetButton.textContent = "Verify Authenticator Code";
        resetSection?.classList.remove("hidden");
        if (resetHelper) resetHelper.textContent = `Open Google Authenticator and enter the current GeoAttend code for ${email}.`;
        showLoginMessage("Enter your Google Authenticator code first.");
      });

      resetButton?.addEventListener("click", async () => {
        const otp = (resetOtp?.value || "").trim();
        const password = newPassword?.value || "";

        if (!resetEmail) {
          showLoginMessage("Open password reset first.", true);
          return;
        }

        if (!otp) {
          showLoginMessage("Enter your Google Authenticator code.", true);
          return;
        }

        if (!resetCodeVerified) {
          resetButton.disabled = true;
          resetButton.textContent = "Verifying Code...";
          try {
            await postJson("/api/verify-password-reset-totp", { email: resetEmail, code: otp });
            resetCodeVerified = true;
            newPasswordStep?.classList.remove("hidden");
            if (resetHelper) resetHelper.textContent = "Authenticator code verified. Now enter a new password.";
            resetButton.textContent = "Update Password";
            showLoginMessage("Code verified. Enter your new password.");
            newPassword?.focus();
          } catch (error) {
            showLoginMessage(error.message, true);
          } finally {
            resetButton.disabled = false;
            if (!resetCodeVerified) resetButton.textContent = "Verify Authenticator Code";
          }
          return;
        }

        if (password.length < 8) {
          showLoginMessage("New password must be at least 8 characters.", true);
          return;
        }

        resetButton.disabled = true;
        resetButton.textContent = "Updating Password...";
        try {
          await postJson("/api/verify-password-reset-totp", { email: resetEmail, code: otp, password });
          const accounts = getAccounts();
          const account = accounts.find((savedAccount) => savedAccount.email === resetEmail);
          if (account) {
            account.password = password;
            account.passwordUpdatedAt = new Date().toISOString();
            saveAccounts(accounts);
          }
          resetSection?.classList.add("hidden");
          newPasswordStep?.classList.add("hidden");
          resetCodeVerified = false;
          if (resetOtp) resetOtp.value = "";
          if (newPassword) newPassword.value = "";
          resetButton.textContent = "Verify Authenticator Code";
          showLoginMessage("Password updated. You can now login with your new password.");
        } catch (error) {
          showLoginMessage(error.message, true);
        } finally {
          resetButton.disabled = false;
          if (resetCodeVerified) resetButton.textContent = "Update Password";
        }
      });
    }

    document.querySelectorAll("[data-login-as]").forEach((button) => {
      button.addEventListener("click", () => {
        const selectedRole = button.dataset.loginAs;
        localStorage.setItem("geoAttendRole", selectedRole);
        localStorage.setItem("geoAttendView", selectedRole === "admin" ? "admin" : "student");
        window.location.href = selectedRole === "admin" ? "dashboard.html" : "student-home.html";
      });
    });

    document.querySelectorAll("[data-logout], a, button").forEach((element) => {
      const label = (element.textContent || "").trim().toLowerCase();
      if (label.includes("logout") || element.hasAttribute("data-logout")) {
        element.addEventListener("click", (event) => {
          event.preventDefault();
          localStorage.removeItem("geoAttendRole");
          localStorage.removeItem("geoAttendView");
          localStorage.removeItem("geoAttendCurrentUser");
          localStorage.removeItem("geoAttendAdminEmail");
          localStorage.removeItem("geoAttendAdminRole");
          localStorage.removeItem("geoAttendAdminName");
          localStorage.removeItem("geoAttendAdminFacultyId");
          localStorage.removeItem("geoAttendAdminFacultyName");
          localStorage.removeItem("geoAttendAdminDepartmentId");
          localStorage.removeItem("geoAttendAdminDepartmentName");
          localStorage.removeItem("geoAttendAdminLevelId");
          localStorage.removeItem("geoAttendAdminLevelName");
        localStorage.removeItem("geoAttendAdminFacultyId");
        localStorage.removeItem("geoAttendAdminFacultyName");
        localStorage.removeItem("geoAttendAdminDepartmentId");
        localStorage.removeItem("geoAttendAdminDepartmentName");
        localStorage.removeItem("geoAttendAdminLevelId");
        localStorage.removeItem("geoAttendAdminLevelName");
          window.location.href = "login.html";
        });
      }
    });

    if (isAdminSession && isAdminPage) {
      sendAdminLoginAudit(currentUserEmail);
    }

    if (role === "admin" && isAdminPage) {
      const switchLink = document.createElement("a");
      switchLink.href = "student-home.html#active-classes";
      switchLink.className = "admin-view-switch bg-secondary text-on-primary rounded-xl px-4 py-2 shadow-lg font-bold inline-flex items-center gap-2 shrink-0";
      switchLink.innerHTML = '<span class="material-symbols-outlined text-[20px]">visibility</span><span>Student View</span>';
      const header = document.querySelector("main > header, main > div > header");
      if (header) {
        header.insertBefore(switchLink, header.firstChild);
      } else {
        switchLink.classList.add("fixed", "top-4", "left-4", "z-[999]");
        document.body.appendChild(switchLink);
      }
      setupAdminProfileMenu();
    }

  if (role === "admin" && isStudentPage) {
      const adminSwitch = document.createElement("a");
      adminSwitch.href = "dashboard.html";
      adminSwitch.className = "admin-view-switch bg-secondary text-on-primary rounded-xl px-4 py-2 shadow-lg font-bold inline-flex items-center gap-2 shrink-0";
      adminSwitch.innerHTML = '<span class="material-symbols-outlined text-[20px]">admin_panel_settings</span><span>Admin View</span>';
      const header = document.querySelector("header");
      if (header) {
        header.insertBefore(adminSwitch, header.firstChild);
      } else {
        adminSwitch.classList.add("fixed", "top-4", "left-4", "z-[999]");
        document.body.appendChild(adminSwitch);
      }
    }

    function setupAdminProfileMenu() {
      const header = document.querySelector("main > header, main > div > header");
      if (!header || document.getElementById("admin-profile-menu-root")) return;
      const currentEmail = localStorage.getItem("geoAttendCurrentUser") || "Admin";
      const currentName = getDisplayName();
      const root = document.createElement("div");
      root.id = "admin-profile-menu-root";
      root.className = "admin-profile-menu-root relative";
      root.innerHTML = `
        <button class="admin-profile-trigger w-10 h-10 rounded-full bg-secondary-fixed text-secondary border border-outline-variant flex items-center justify-center" type="button" aria-expanded="false" aria-label="Admin profile menu">
          <span class="material-symbols-outlined">person</span>
        </button>
        <div class="admin-profile-menu hidden absolute right-0 top-12 w-72 rounded-xl border border-outline-variant bg-surface-container-lowest shadow-2xl z-[999] p-3">
          <div class="border-b border-outline-variant pb-3 mb-3">
            <p class="text-xs font-bold uppercase tracking-widest text-on-surface-variant">Admin Account</p>
            <p class="font-bold text-on-surface break-words">${escapeLocalHtml(currentName)}</p>
            <p class="text-xs text-on-surface-variant break-words">${escapeLocalHtml(currentEmail)}</p>
          </div>
          <a class="flex items-center gap-2 rounded-lg px-3 py-2 font-bold text-on-surface hover:bg-surface-container-low" href="admin-management.html">
            <span class="material-symbols-outlined text-[20px]">admin_panel_settings</span>
            Manage Admins
          </a>
          <a class="flex items-center gap-2 rounded-lg px-3 py-2 font-bold text-on-surface hover:bg-surface-container-low" href="student-home.html#active-classes">
            <span class="material-symbols-outlined text-[20px]">how_to_reg</span>
            Admin Check-in
          </a>
          <button class="admin-theme-toggle mt-1 flex w-full items-center gap-2 rounded-lg px-3 py-2 font-bold text-on-surface hover:bg-surface-container-low" type="button">
            <span class="material-symbols-outlined text-[20px]">dark_mode</span>
            <span>${document.documentElement.classList.contains("dark") ? "Switch to Light Mode" : "Switch to Dark Mode"}</span>
          </button>
        </div>
      `;
      const headerRight = header.lastElementChild;
      if (headerRight && headerRight !== header.firstElementChild) {
        headerRight.appendChild(root);
      } else {
        header.appendChild(root);
      }

      const trigger = root.querySelector(".admin-profile-trigger");
      const menu = root.querySelector(".admin-profile-menu");
      const themeToggle = root.querySelector(".admin-theme-toggle");
      trigger?.addEventListener("click", (event) => {
        event.stopPropagation();
        const isOpen = !menu.classList.contains("hidden");
        menu.classList.toggle("hidden", isOpen);
        trigger.setAttribute("aria-expanded", String(!isOpen));
      });
      themeToggle?.addEventListener("click", () => {
        const nextTheme = document.documentElement.classList.contains("dark") ? "light" : "dark";
        localStorage.setItem("geoAttendTheme", nextTheme);
        document.documentElement.classList.toggle("dark", nextTheme === "dark");
        document.documentElement.classList.toggle("light", nextTheme !== "dark");
        const icon = themeToggle.querySelector(".material-symbols-outlined");
        const label = themeToggle.querySelector("span:last-child");
        if (icon) icon.textContent = nextTheme === "dark" ? "light_mode" : "dark_mode";
        if (label) label.textContent = nextTheme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode";
      });
      document.addEventListener("click", (event) => {
        if (!root.contains(event.target)) {
          menu?.classList.add("hidden");
          trigger?.setAttribute("aria-expanded", "false");
        }
      });
    }

    function escapeLocalHtml(value) {
      return String(value || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function updateHeaderIdentity() {
      const displayName = getDisplayName();
      document.querySelectorAll("[data-current-user-name]").forEach((node) => {
        node.textContent = displayName;
      });

      if (role === "admin") {
        document.querySelectorAll("main > header .text-right p:first-child, main > header .hidden p:first-child").forEach((node) => {
        });
      }

      if (role === "student") {
        document.querySelectorAll("[data-student-user-name]").forEach((node) => {
          node.textContent = displayName;
        });
      }
    }
  });
})();
