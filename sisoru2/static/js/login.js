// Login Form Submission
document.querySelector("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault(); // Prevent default form submission
    const email = document.querySelector("#email").value;
    const password = document.querySelector("#password").value;

    const response = await fetch("/auth_login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
    });

    const result = await response.json();
    if (result.success) {
        window.location.href = result.redirect; // Redirect to dashboard
    } else {
        document.querySelector("#error-message").textContent = result.message;
    }
});

// Registration Form Submission
document.querySelector("#register-form").addEventListener("submit", async (event) => {
    event.preventDefault(); // Prevent default form submission
    const username = document.querySelector("#username").value;
    const email = document.querySelector("#email").value;
    const password = document.querySelector("#password").value;

    const response = await fetch("/auth_register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password })
    });

    const result = await response.json();
    if (result.success) {
        window.location.href = result.redirect; // Redirect to login
    } else {
        document.querySelector("#error-message").textContent = result.message;
    }
});
