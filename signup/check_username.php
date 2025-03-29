<?php
include '../config.php';
$query = new Database();

if (isset($_POST['username'])) {
    $username = $_POST['username'];
    
    $stmt = $query->conn->prepare("SELECT * FROM accounts WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo 'exists';
    } else {
        echo '';
    }
}
?>
