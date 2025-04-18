<?php
session_start();

include '../config.php';
$query = new Database();

// Generate CSRF token if it doesn't exist
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
    if ($_SESSION['role'] == 'admin') {
        header("Location: ../admin/");
        exit;
    } else if ($_SESSION['role'] == 'seller') {
        header("Location: ../seller/");
        exit;
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
            exit;
        } else {
            header("Location: ../");
            exit;
        }
    }
}

$msg = [];

if (isset($_POST['submit'])) {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $msg = [
            "title" => "Error!",
            "text" => "Invalid form submission."
        ];
    } else {
        $name = $_POST['name'];
        $number = $_POST['number'];
        $role = $_POST['role'];
        
        // Restrict role to only 'user' and 'seller'
        if ($role !== 'user' && $role !== 'seller') {
            $role = 'user'; // Default to user if invalid role
        }
        
        $email = $_POST['email'];
        $username = $_POST['username'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        
        // Check if passwords match
        if ($password !== $confirm_password) {
            $msg = [
                "title" => "Error!",
                "text" => "Passwords do not match."
            ];
        } else {
            $existingUser = $query->executeQueryWithParams(
                "SELECT * FROM accounts WHERE username = ? OR email = ? OR number = ?",
                [$username, $email, $number]
            );

            if ($existingUser->num_rows > 0) {
                $msg = [
                    "title" => "Error!",
                    "text" => "Username, email, or phone number already exists."
                ];
            } else {
                $result = $query->registerUser($name, $number, $email, $username, $password, $role);
                $userData = $query->executeQueryWithParams("SELECT * FROM accounts WHERE username = ?", [$username])->fetch_assoc();

                if (!empty($result) && !empty($userData) && isset($userData['id'])) {
                    $_SESSION['loggedin'] = true;
                    $_SESSION['id'] = $userData['id'];
                    $_SESSION['name'] = $name;
                    $_SESSION['number'] = $number;
                    $_SESSION['email'] = $email;
                    $_SESSION['username'] = $username;
                    $_SESSION['role'] = $role;

                    setcookie('username', $username, time() + (86400 * 30), "/", "", true, true);
                    setcookie('session_token',  session_id(), time() + (86400 * 30), "/", "", true, true);

                    $msg = [
                        "title" => "Success!",
                        "text" => "Registration completed!",
                        "icon" => "success"
                    ];

                    if ($role === 'admin') {
                        header("Location: ../admin/");
                        exit;
                    } else if ($role === 'seller') {
                        header("Location: ../seller/");
                        exit;
                    } else {
                        header("Location: ../");
                        exit;
                    }
                } else {
                    $msg = [
                        "title" => "Error!",
                        "text" => "An error occurred while saving the data."
                    ];
                }
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
    <title>Sign Up</title>
    <link rel="stylesheet" href="../src/css/login.css">
    <link rel="icon" href="../favicon.ico">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        .error-message {
            color: red;
            font-size: 12px;
            margin-top: 5px;
        }

        body {
            padding: 40px 0px !important;
        }
    </style>
</head>

<body>
    <?php if (!empty($msg)): ?>
        <script>
            Swal.fire({
                title: "<?php echo htmlspecialchars($msg['title'], ENT_QUOTES, 'UTF-8'); ?>",
                text: "<?php echo htmlspecialchars($msg['text'], ENT_QUOTES, 'UTF-8'); ?>",
                icon: "<?php echo htmlspecialchars($msg['icon'] ?? 'error', ENT_QUOTES, 'UTF-8'); ?>",
                confirmButtonText: "OK"
            });
        </script>
    <?php endif; ?>

    <div class="form-container">

        <h2>Sign Up</h2>

        <form method="post" action="" enctype="multipart/form-data" id="signup-form">
            <!-- Add CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            
            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" name="name" placeholder="Full Name" required maxlength="30">
            </div>

            <div class="form-group">
                <label for="number">Number</label>
                <input type="phone" name="number" placeholder="Tell: +998991234567" required maxlength="20">
                <p class="error-message" id="number-error"></p>
            </div>

            <div class="form-group">
                <label for="role" class="font-weight-bold">Role</label>
                <select id="role" name="role" class="form-control" required>
                    <option value="" disabled selected>Select Role</option>
                    <option value="user">User</option>
                    <option value="seller">Seller</option>
                </select>
            </div>


            <div class="form-group">
                <label for="name">Email</label>
                <input type="email" name="email" placeholder="Email" required maxlength="255">
                <p class="error-message" id="email-error"></p>
            </div>

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" placeholder="Username" required maxlength="255">
                <p class="error-message" id="username-error"></p>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <div class="password-container">
                    <input type="password" id="password" name="password" required maxlength="255">
                    <button type="button" id="toggle-password" class="password-toggle"><i
                            class="fas fa-eye"></i></button>
                </div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <div class="password-container">
                    <input type="password" id="confirm_password" name="confirm_password" required maxlength="255">
                    <button type="button" id="toggle-confirm-password" class="password-toggle"><i
                            class="fas fa-eye"></i></button>
                </div>
                <p class="error-message" id="password-match-error"></p>
            </div>

            <div class="form-group">
                <input type="submit" name="submit" id="submit" value="Submit">
            </div>

            <div class="text-center">
                <p>Already have an account? <a href="../login/">Log in</a></p>
            </div>
        </form>

    </div>

    <script>
        $('#file-input').on('change', function() {
            var fileName = $(this).val().split('\\').pop();
            $(this).next('.custom-file-label').html(fileName);
        });

        document.getElementById('toggle-password').addEventListener('click', function() {
            const passwordField = document.getElementById('password');
            const toggleIcon = this.querySelector('i');

            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                toggleIcon.classList.remove('fa-eye');
                toggleIcon.classList.add('fa-eye-slash');
            } else {
                passwordField.type = 'password';
                toggleIcon.classList.remove('fa-eye-slash');
                toggleIcon.classList.add('fa-eye');
            }
        });
        
        document.getElementById('toggle-confirm-password').addEventListener('click', function() {
            const passwordField = document.getElementById('confirm_password');
            const toggleIcon = this.querySelector('i');

            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                toggleIcon.classList.remove('fa-eye');
                toggleIcon.classList.add('fa-eye-slash');
            } else {
                passwordField.type = 'password';
                toggleIcon.classList.remove('fa-eye-slash');
                toggleIcon.classList.add('fa-eye');
            }
        });

        $(document).ready(function() {
            // Password match validation
            $('#password, #confirm_password').on('keyup', function() {
                if ($('#password').val() !== '' && $('#confirm_password').val() !== '') {
                    if ($('#password').val() === $('#confirm_password').val()) {
                        $('#password-match-error').text('');
                        $('#submit').prop('disabled', false);
                    } else {
                        $('#password-match-error').text('Passwords do not match');
                        $('#submit').prop('disabled', true);
                    }
                }
            });
            
            $('input[name="number"]').on('input', function() {
                var number = $(this).val();
                if (number.length > 0 && !/^\d+$/.test(number)) {
                    $('#number-error').text('Number must contain only digits');
                } else {
                    $('#number-error').text('');
                }
            });

            $('input[name="email"]').on('input', function() {
                var email = $(this).val();
                if (email.length > 0 && !/\S+@\S+\.\S+/.test(email)) {
                    $('#email-error').text('Invalid email.');
                } else {
                    $('#email-error').text('');
                }
            });
        });


        $(document).ready(function() {
            var button_active = true;

            function isOne(value, callback) {
                $.ajax({
                    url: 'check_username.php',
                    type: 'POST',
                    data: {
                        username: value
                    },
                    success: function(response) {
                        if (response === 'exists') {
                            callback(true);
                        } else {
                            callback(false);
                        }
                    }
                });
            }

            function toggleSubmitButton() {
                if (button_active) {
                    $('#submit').prop('disabled', false);
                } else {
                    $('#submit').prop('disabled', true);
                }
            }

            $('input[name="username"]').on('input', function() {
                var username = $(this).val();
                if (username.length > 0 && !/^[a-zA-Z0-9_]+$/.test(username)) {
                    $('#username-error').text('Username can only contain letters, numbers, and underscores!');
                    button_active = false;
                } else {
                    $('#username-error').text('');
                    button_active = true;

                    if (username.length > 0) {
                        isOne(username, function(result) {
                            if (result) {
                                $('#username-error').text('This username already exists.');
                                button_active = false;
                            } else {
                                $('#username-error').text('');
                                toggleSubmitButton();
                            }
                        });
                    } else {
                        toggleSubmitButton();
                    }
                }

                toggleSubmitButton();
            });
        });

        $(document).ready(function() {
            function isEmailExists(email, callback) {
                $.ajax({
                    url: 'check_email.php',
                    type: 'POST',
                    data: {
                        email: email
                    },
                    success: function(response) {
                        if (response === 'exists') {
                            callback(true);
                        } else {
                            callback(false);
                        }
                    }
                });
            }

            $('input[name="email"]').on('input', function() {
                var email = $(this).val();
                if (email.length > 0 && !isValidEmail(email)) {
                    $('#email-error').text('Invalid email.');
                } else {
                    $('#email-error').text('');
                }
                if (email.length > 0) {
                    isEmailExists(email, function(result) {
                        if (result) {
                            $('#email-error').text('This email already exists.');
                        } else {
                            $('#email-error').text('');
                        }
                    });
                }
            });

            function isValidEmail(email) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
            }
        });

        $(document).ready(function() {
            function isNumberExists(number, callback) {
                $.ajax({
                    url: 'check_number.php',
                    type: 'POST',
                    data: {
                        number: number
                    },
                    success: function(response) {
                        if (response === 'exists') {
                            callback(true);
                        } else {
                            callback(false);
                        }
                    }
                });
            }

            $('input[name="number"]').on('input', function() {
                var number = $(this).val();
                if (number.length > 0 && !/^\d+$/.test(number)) {
                    $('#number-error').text('Number must contain only digits');
                } else {
                    $('#number-error').text('');
                }
                if (number.length > 0) {
                    isNumberExists(number, function(result) {
                        if (result) {
                            $('#number-error').text('This number already exists.');
                        } else {
                            $('#number-error').text('');
                        }
                    });
                }
            });
        });

        function hideErrorMessage() {
            $('.error').hide();
        }
    </script>

    <?php if (isset($msg)): ?>
        <script>
            $(document).ready(function() {
                setTimeout(function() {
                    hideErrorMessage();
                }, 4000);
            });
        </script>
    <?php endif ?>

</body>

</html>
