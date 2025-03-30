<?php
require_once '../includes/security.php';
secureSession();

include '../config.php';
$query = new Database();

if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
    if ($_SESSION['role'] == 'admin') {
        header("Location: ../admin/");
        exit;
    } else if ($_SESSION['role'] == 'seller') {
        header("Location: ../seller/");
    } else {
        header("Location: ../");
        exit;
    }
}

if (isset($_COOKIE['username']) && isset($_COOKIE['session_token'])) {

    if (session_id() !== $_COOKIE['session_token']) {
        session_write_close();
        session_id($_COOKIE['session_token']);
        session_start();
    }

    $username = $_COOKIE['username'];

    $result = $query->select('accounts', 'id, role', "WHERE username = ?", [$username]);
 
    if (!empty($result)) {
        $user = $result[0];

        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = $_COOKIE['username'];
        $_SESSION['id'] = $user['id'];
        $_SESSION['role'] = $user['role'];

        if ($user['role'] == 'admin') {
            header("Location: ../admin/");
            exit;
        } else if ($user['role'] == 'seller') {
            header("Location: ../seller/");
        } else {
            header("Location: ../");
            exit;
        }
    }
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid request';
    } else {
        // Sanitize input
        $username = sanitizeInput($_POST['username']);
        $password = $_POST['password'];

        // Check rate limiting
        if (!checkRateLimit($_SERVER['REMOTE_ADDR'])) {
            $error = 'Too many login attempts. Please try again later.';
        } else {
            // Verify credentials using Database class
            $result = $query->authenticate($username, $password, 'accounts');
            
            if (!empty($result)) {
                $user = $result[0];
                $_SESSION['loggedin'] = true;
                $_SESSION['username'] = $username;
                $_SESSION['id'] = $user['id'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['created'] = time();

                // Set secure cookie
                $session_token = session_id();
                setcookie('username', $username, time() + (86400 * 30), '/', '', true, true);
                setcookie('session_token', $session_token, time() + (86400 * 30), '/', '', true, true);

                if ($user['role'] == 'admin') {
                    header("Location: ../admin/");
                    exit;
                } else if ($user['role'] == 'seller') {
                    header("Location: ../seller/");
                    exit;
                } else {
                    header("Location: ../");
                    exit;
                }
            } else {
                $error = 'Invalid username or password';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="icon" href="../favicon.ico">
    <link rel="stylesheet" href="../src/css/login.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        body {
            height: 100vh;
        }

        .error-message {
            color: red;
            font-size: 12px;
            margin-top: 5px;
        }
    </style>
</head>

<body>
    <div class="form-container">
        <h1>Login</h1>
        <?php if ($error): ?>
            <div class="error-message"><?php echo sanitizeOutput($error); ?></div>
        <?php endif; ?>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" required maxlength="255">
                <p class="error-message" id="username-error"></p>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <div class="password-container">
                    <input type="password" id="password" name="password" required maxlength="255">
                    <button type="button" id="toggle-password" class="password-toggle"><i class="fas fa-eye"></i></button>
                </div>
            </div>
            <div class="form-group">
                <button type="submit" name="submit" id="submit">Login</button>
            </div>
        </form>

        <div class="text-center">
            <p>Don't have an account? <a href="../signup/">Sign Up</a></p>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            <?php if ($error): ?>
                Swal.fire({
                    icon: 'error',
                    title: 'Oops...',
                    text: '<?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>',
                    position: 'top-end',
                    toast: true,
                    showConfirmButton: false,
                    timer: 3000
                });
            <?php endif; ?>

            document.getElementById('toggle-password').addEventListener('click', function() {
                const passwordField = document.getElementById('password');
                const toggleIcon = this.querySelector('i');

                if (passwordField.type === 'password') {
                    passwordField.type = 'text';
                    toggleIcon.classList.replace('fa-eye', 'fa-eye-slash');
                } else {
                    passwordField.type = 'password';
                    toggleIcon.classList.replace('fa-eye-slash', 'fa-eye');
                }
            });

            const usernameInput = document.getElementById('username');
            const errorElement = document.getElementById('username-error');
            const usernameRegex = /^[a-zA-Z0-9_]+$/;

            usernameInput.addEventListener('input', function() {
                const usernameValue = this.value;

                if (usernameValue && !usernameRegex.test(usernameValue)) {
                    errorElement.textContent = "Username can only contain letters, numbers, and underscores!";
                } else {
                    errorElement.textContent = "";
                }
            });

            const form = document.querySelector('form');
            form.addEventListener('submit', function(event) {
                if (!usernameRegex.test(usernameInput.value)) {
                    event.preventDefault();
                    errorElement.textContent = "Username can only contain letters, numbers, and underscores!";
                }
            });
        });
    </script>

</body>

</html>
