<?php
session_start();

$conn = mysqli_connect("localhost", "root", "", "todo");
if (!$conn) {
    die(json_encode(["status" => "error", "message" => "Database connection failed"]));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    switch ($action) {
        case "signup":
            signUp($conn);
            break;
        case "signin":
            signIn($conn);
            break;
        case "fetch":
            fetchNotes($conn); 
            break;
        case "add":
            addNote($conn);
            break;
        case "update":
            updateNote($conn);
            break;
        case "delete":
            deleteNote($conn);
            break;
        default:
            echo json_encode(["status" => "error", "message" => "Invalid action"]);
            exit;
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    fetchUsers($conn);
}

mysqli_close($conn);

// Fetch all user
function fetchUsers($conn) {
    $query = "SELECT * FROM users";
    $query_run = mysqli_query($conn, $query);

    $result = [];
    if ($query_run) {
        while ($row = mysqli_fetch_assoc($query_run)) {
            $result[] = $row;
        }
        echo json_encode($result);
    } else {
        echo json_encode(["status" => "error", "message" => "Failed to fetch users"]);
    }
    exit;
}

// User signup
function signUp($conn) {
    if (!isset($_POST['email'], $_POST['username'], $_POST['password'], $_POST['gender'])) {
        echo json_encode(["status" => "error", "message" => "Missing required fields"]);
        exit;
    }

    $email = trim($_POST['email']);
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $gender = trim($_POST['gender']);

    if (strlen($password) < 8) {
        echo json_encode(["status" => "error", "message" => "Password must be at least 8 characters long"]);
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(["status" => "error", "message" => "Invalid email format"]);
        exit;
    }

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $query = "INSERT INTO users (name, email, password, gender) VALUES (?, ?, ?, ?)";
    $stmt = mysqli_prepare($conn, $query);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "ssss", $username, $email, $hashedPassword, $gender);
        if (mysqli_stmt_execute($stmt)) {
            echo json_encode(["status" => "success", "message" => "User registered successfully"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Registration failed"]);
        }
        mysqli_stmt_close($stmt);
    } else {
        echo json_encode(["status" => "error", "message" => "SQL statement preparation failed"]);
    }
    exit;
}

// User signin
function signIn($conn) {
    if (!isset($_POST['email'], $_POST['password'])) {
        echo json_encode(["status" => "error", "message" => "Email and password required"]);
        exit;
    }

    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    $query = "SELECT * FROM users WHERE email = ?";
    $stmt = mysqli_prepare($conn, $query);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $user = mysqli_fetch_assoc($result);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['email'] = $user['email'];
            echo json_encode(["status" => "success", "message" => "Login successful"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Invalid email or password"]);
        }
        mysqli_stmt_close($stmt);
    } else {
        echo json_encode(["status" => "error", "message" => "SQL query failed"]);
    }
    exit;
}

// Fetch notes for the logged-in user
function fetchNotes($conn) {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(["status" => "error", "message" => "User not logged in"]);
        exit;
    }

    $userId = $_SESSION['user_id'];
    $query = "SELECT note_id, notes, date_created FROM notes WHERE userid = ?";
    $stmt = mysqli_prepare($conn, $query);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "i", $userId);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        $notes = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $notes[] = $row;
        }

        echo json_encode(["status" => "success", "notes" => $notes]);
        mysqli_stmt_close($stmt);
    } else {
        echo json_encode(["status" => "error", "message" => "Failed to fetch notes"]);
    }
    exit;
}

// Add a new note
function addNote($conn) {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(["status" => "error", "message" => "User not logged in"]);
        exit;
    }

    if (!isset($_POST['note'])) {
        echo json_encode(["status" => "error", "message" => "Note content required"]);
        exit;
    }

    $userId = $_SESSION['user_id'];
    $note = trim($_POST['note']);
    $dateCreated = date('Y-m-d H:i:s'); // Current timestamp

    $query = "INSERT INTO notes (userid, notes, date_created) VALUES (?, ?, ?)";
    $stmt = mysqli_prepare($conn, $query);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "iss", $userId, $note, $dateCreated);
        if (mysqli_stmt_execute($stmt)) {
            echo json_encode(["status" => "success", "message" => "Note added successfully"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Failed to add note"]);
        }
        mysqli_stmt_close($stmt);
    } else {
        echo json_encode(["status" => "error", "message" => "SQL statement preparation failed"]);
    }
    exit;
}

// Update an existing note
function updateNote($conn) {
    if (!isset($_POST['id'], $_POST['note'])) {
        echo json_encode(["status" => "error", "message" => "Note ID and content required"]);
        exit;
    }

    $id = $_POST['id'];
    $note = trim($_POST['note']);

    $query = "UPDATE notes SET notes = ? WHERE note_id = ?";
    $stmt = mysqli_prepare($conn, $query);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "si", $note, $id);
        if (mysqli_stmt_execute($stmt)) {
            echo json_encode(["status" => "success", "message" => "Note updated successfully"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Failed to update note"]);
        }
        mysqli_stmt_close($stmt);
    } else {
        echo json_encode(["status" => "error", "message" => "SQL statement preparation failed"]);
    }
    exit;
}

// Delete a note
function deleteNote($conn) {
    if (!isset($_POST['id'])) {
        echo json_encode(["status" => "error", "message" => "Note ID required"]);
        exit;
    }

    $id = $_POST['id'];

    $query = "DELETE FROM notes WHERE note_id = ?";
    $stmt = mysqli_prepare($conn, $query);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "i", $id);
        if (mysqli_stmt_execute($stmt)) {
            echo json_encode(["status" => "success", "message" => "Note deleted successfully"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Failed to delete note"]);
        }
        mysqli_stmt_close($stmt);
    } else {
        echo json_encode(["status" => "error", "message" => "SQL statement preparation failed"]);
    }
    exit;
}
?>