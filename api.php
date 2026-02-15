<?php
error_reporting(0);
ini_set('display_errors', 0);
session_start();

header('Content-Type: application/json');

$host = 'localhost';
$db   = 'dashboard';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    echo json_encode(['error' => 'Database verbinding mislukt: ' . $e->getMessage()]);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'getUsers':
        getUsers($pdo);
        break;
    case 'addUser':
        requireAdmin($pdo);
        addUser($pdo);
        break;
    case 'updateUser':
        requireAdmin($pdo);
        updateUser($pdo);
        break;
    case 'deleteUser':
        requireAdmin($pdo);
        deleteUser($pdo);
        break;
    case 'getRoles':
        getRoles($pdo);
        break;
    case 'getContentTypes':
        getContentTypes($pdo);
        break;
    case 'addContentType':
        requireAdmin($pdo);
        addContentType($pdo);
        break;
    case 'updateContentType':
        requireAdmin($pdo);
        updateContentType($pdo);
        break;
    case 'deleteContentType':
        requireAdmin($pdo);
        deleteContentType($pdo);
        break;
    case 'addRole':
        requireAdmin($pdo);
        addRole($pdo);
        break;
    case 'updateRole':
        requireAdmin($pdo);
        updateRole($pdo);
        break;
    case 'deleteRole':
        requireAdmin($pdo);
        deleteRole($pdo);
        break;
    case 'getBlogs':
        getBlogs($pdo);
        break;
    case 'addBlog':
        requireLogin($pdo);
        addBlog($pdo);
        break;
    case 'updateBlog':
        requireLogin($pdo);
        updateBlog($pdo);
        break;
    case 'deleteBlog':
        requireAdmin($pdo);
        deleteBlog($pdo);
        break;
    case 'uploadImage':
        uploadImage($pdo);
        break;
    case 'getUserImages':
        requireLogin($pdo);
        getUserImages($pdo);
        break;
    case 'login':
        login($pdo);
        break;
    case 'register':
        register($pdo);
        break;
    case 'checkEmail':
        checkEmail($pdo);
        break;
    case 'checkName':
        checkName($pdo);
        break;
    case 'logout':
        logout();
        break;
    case 'checkSession':
        checkSession($pdo);
        break;
    case 'getUserStats':
        requireAdmin($pdo);
        getUserStats($pdo);
        break;
    case 'getPendingUsers':
        requireAdmin($pdo);
        getPendingUsers($pdo);
        break;
    case 'approveUser':
        requireAdmin($pdo);
        approveUser($pdo);
        break;
    case 'rejectUser':
        requireAdmin($pdo);
        rejectUser($pdo);
        break;
    case 'blockUser':
        requireAdmin($pdo);
        blockUser($pdo);
        break;
    case 'unblockUser':
        requireAdmin($pdo);
        unblockUser($pdo);
        break;
    default:
        echo json_encode(['error' => 'Ongeldige actie']);
}

function getUsers($pdo) {
    $stmt = $pdo->query("SELECT * FROM gebruikers ORDER BY created_at DESC");
    $users = $stmt->fetchAll();
    echo json_encode($users);
}

function addUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $stmt = $pdo->prepare("INSERT INTO gebruikers (voornaam, tussenvoegsel, achternaam, emailadres, rol) VALUES (?, ?, ?, ?, ?)");
    
    try {
        $stmt->execute([
            $data['voornaam'],
            $data['tussenvoegsel'] ?? '',
            $data['achternaam'],
            $data['emailadres'],
            $data['rol']
        ]);
        echo json_encode(['success' => true, 'id' => $pdo->lastInsertId()]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function updateUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $stmt = $pdo->prepare("UPDATE gebruikers SET voornaam = ?, tussenvoegsel = ?, achternaam = ?, emailadres = ?, rol = ? WHERE id = ?");
    
    try {
        $stmt->execute([
            $data['voornaam'],
            $data['tussenvoegsel'] ?? '',
            $data['achternaam'],
            $data['emailadres'],
            $data['rol'],
            $data['id']
        ]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function deleteUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $stmt = $pdo->prepare("DELETE FROM gebruikers WHERE id = ?");
    
    try {
        $stmt->execute([$data['id']]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function getRoles($pdo) {
    $stmt = $pdo->query("SELECT * FROM rollen ORDER BY id");
    $roles = $stmt->fetchAll();
    
    foreach ($roles as &$role) {
        if (isset($role['permissions'])) {
            $role['permissions'] = json_decode($role['permissions'], true);
        } else {
            $role['permissions'] = [];
        }
    }
    
    echo json_encode($roles);
}

function addRole($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $naam = $data['naam'] ?? '';
    $permissions = $data['permissions'] ?? [];
    
    if (!$naam) {
        echo json_encode(['error' => 'Rolnaam is verplicht']);
        return;
    }
    
    $permissionsJson = json_encode($permissions);
    
    $stmt = $pdo->prepare("INSERT INTO rollen (naam, permissions) VALUES (?, ?)");
    
    try {
        $stmt->execute([$naam, $permissionsJson]);
        echo json_encode(['success' => true, 'id' => $pdo->lastInsertId()]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function updateRole($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? 0;
    $naam = $data['naam'] ?? '';
    $permissions = $data['permissions'] ?? [];
    
    if (!$naam || !$id) {
        echo json_encode(['error' => 'Rolnaam is verplicht']);
        return;
    }
    
    $permissionsJson = json_encode($permissions);
    
    $stmt = $pdo->prepare("UPDATE rollen SET naam = ?, permissions = ? WHERE id = ?");
    
    try {
        $stmt->execute([$naam, $permissionsJson, $id]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function deleteRole($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $stmt = $pdo->prepare("DELETE FROM rollen WHERE id = ?");
    
    try {
        $stmt->execute([$data['id']]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function login($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $emailadres = $data['emailadres'] ?? '';
    $code = $data['code'] ?? '';
    
    if ($code) {
        // Verifieer inlogcode
        if (!isset($_SESSION['login_code']) || !isset($_SESSION['login_email'])) {
            echo json_encode(['error' => 'Verificatiecode verlopen. Vraag een nieuwe code aan.']);
            return;
        }
        
        if ($code !== $_SESSION['login_code'] || $emailadres !== $_SESSION['login_email']) {
            echo json_encode(['error' => 'Ongeldige verificatiecode']);
            return;
        }
        
        $stmt = $pdo->prepare("SELECT * FROM gebruikers WHERE emailadres = ?");
        $stmt->execute([$emailadres]);
        $user = $stmt->fetch();
        
        if (!$user) {
            echo json_encode(['error' => 'Gebruiker niet gevonden']);
            return;
        }
        
        // Check gebruiker status
        $status = $user['status'] ?? 'pending';
        if ($status === 'pending') {
            echo json_encode(['error' => 'Je account is nog niet goedgekeurd. Je ontvangt een email zodra je account is goedgekeurd.']);
            return;
        }
        if ($status === 'blocked') {
            echo json_encode(['error' => 'Je account is geblokkeerd. Neem contact op met de beheerder.']);
            return;
        }
        
        unset($_SESSION['login_code']);
        unset($_SESSION['login_email']);
        
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['rol'] = $user['rol'];
        $_SESSION['naam'] = $user['voornaam'] . ' ' . $user['achternaam'];
        $_SESSION['profielfoto'] = $user['profielfoto'] ?? '';
        
        echo json_encode([
            'success' => true,
            'user' => [
                'id' => $user['id'],
                'naam' => $user['voornaam'] . ' ' . $user['achternaam'],
                'rol' => $user['rol'],
                'status' => $status,
                'profielfoto' => $user['profielfoto'] ?? ''
            ]
        ]);
        return;
    }
    
    // Verzoek inlogcode - frontend stuurt de email via emailJS
    if (!$emailadres) {
        echo json_encode(['error' => 'Emailadres is verplicht']);
        return;
    }
    
    $stmt = $pdo->prepare("SELECT * FROM gebruikers WHERE emailadres = ?");
    $stmt->execute([$emailadres]);
    $user = $stmt->fetch();
    
    if (!$user) {
        echo json_encode(['error' => 'Emailadres niet gevonden']);
        return;
    }
    
    // Check gebruiker status voordat code wordt verstuurd
    $status = $user['status'] ?? 'pending';
    if ($status === 'pending') {
        echo json_encode(['error' => 'Je account is nog niet goedgekeurd. Je ontvangt een email zodra je account is goedgekeurd.']);
        return;
    }
    if ($status === 'blocked') {
        echo json_encode(['error' => 'Je account is geblokkeerd. Neem contact op met de beheerder.']);
        return;
    }
    
    // Genereer verificatiecode en bewaar in sessie
    $loginCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $_SESSION['login_code'] = $loginCode;
    $_SESSION['login_email'] = $emailadres;
    
    // Geef frontend de info om email te versturen
    echo json_encode([
        'send_email' => true,
        'email' => $emailadres,
        'code' => $loginCode,
        'voornaam' => $user['voornaam']
    ]);
}

function register($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $voornaam = trim($data['voornaam'] ?? '');
    $tussenvoegsel = trim($data['tussenvoegsel'] ?? '');
    $achternaam = trim($data['achternaam'] ?? '');
    $emailadres = trim($data['emailadres'] ?? '');
    $profielfoto = $data['profielfoto'] ?? '';
    
    if (!$voornaam || !$achternaam || !$emailadres) {
        echo json_encode(['error' => 'Alle velden zijn verplicht']);
        return;
    }
    
    $fullName = trim($voornaam . ' ' . $tussenvoegsel . ' ' . $achternaam);
    
    $stmt = $pdo->prepare("SELECT id, status FROM gebruikers WHERE TRIM(CONCAT(voornaam, ' ', IFNULL(tussenvoegsel, ''), ' ', achternaam)) = ?");
    $stmt->execute([$fullName]);
    $existingUser = $stmt->fetch();
    if ($existingUser) {
        if ($existingUser['status'] === 'blocked') {
            echo json_encode(['error' => 'Dit account is geblokkeerd. Neem contact op met de beheerder.']);
        } else {
            echo json_encode(['error' => 'Deze gebruiker bestaat al']);
        }
        return;
    }
    
    $fullNameWithEmptyTussenvoegsel = trim($voornaam . '  ' . $achternaam);
    $stmt = $pdo->prepare("SELECT id, status FROM gebruikers WHERE TRIM(CONCAT(voornaam, ' ', IFNULL(tussenvoegsel, ''), ' ', achternaam)) = ?");
    $stmt->execute([$fullNameWithEmptyTussenvoegsel]);
    $existingUser = $stmt->fetch();
    if ($existingUser) {
        if ($existingUser['status'] === 'blocked') {
            echo json_encode(['error' => 'Dit account is geblokkeerd. Neem contact op met de beheerder.']);
        } else {
            echo json_encode(['error' => 'Deze gebruiker bestaat al']);
        }
        return;
    }
    
    $stmt = $pdo->prepare("SELECT id, status FROM gebruikers WHERE emailadres = ?");
    $stmt->execute([$emailadres]);
    $existingUser = $stmt->fetch();
    if ($existingUser) {
        if ($existingUser['status'] === 'blocked') {
            echo json_encode(['error' => 'Dit emailadres is geblokkeerd. Neem contact op met de beheerder.']);
        } else {
            echo json_encode(['error' => 'Emailadres al in gebruik']);
        }
        return;
    }
    
    $stmt = $pdo->prepare("INSERT INTO gebruikers (voornaam, tussenvoegsel, achternaam, emailadres, rol, profielfoto, status) VALUES (?, ?, ?, ?, 'Gebruiker', ?, 'active')");
    
    try {
        $stmt->execute([$voornaam, $tussenvoegsel, $achternaam, $emailadres, $profielfoto]);
        
        echo json_encode([
            'success' => true, 
            'message' => 'Je account is aangemaakt! Je kunt nu inloggen.'
        ]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function checkEmail($pdo) {
    $emailadres = $_GET['email'] ?? '';
    $exclude_id = isset($_GET['exclude_id']) ? (int)$_GET['exclude_id'] : null;
    
    if (!$emailadres) {
        echo json_encode(['exists' => false]);
        return;
    }
    
    if ($exclude_id) {
        $stmt = $pdo->prepare("SELECT id, status FROM gebruikers WHERE emailadres = ? AND id != ?");
        $stmt->execute([$emailadres, $exclude_id]);
    } else {
        $stmt = $pdo->prepare("SELECT id, status FROM gebruikers WHERE emailadres = ?");
        $stmt->execute([$emailadres]);
    }
    $user = $stmt->fetch();
    
    if (!$user) {
        echo json_encode(['exists' => false]);
        return;
    }
    
    if ($user['status'] === 'blocked') {
        echo json_encode(['exists' => true, 'blocked' => true]);
        return;
    }
    
    echo json_encode(['exists' => true, 'blocked' => false]);
}

function checkName($pdo) {
    $voornaam = $_GET['voornaam'] ?? '';
    $tussenvoegsel = $_GET['tussenvoegsel'] ?? '';
    $achternaam = $_GET['achternaam'] ?? '';
    $exclude_id = isset($_GET['exclude_id']) ? (int)$_GET['exclude_id'] : null;
    
    if (!$voornaam || !$achternaam) {
        echo json_encode(['exists' => false]);
        return;
    }
    
    $fullName = trim($voornaam . ' ' . $tussenvoegsel . ' ' . $achternaam);
    
    if ($exclude_id) {
        $stmt = $pdo->prepare("SELECT id FROM gebruikers WHERE TRIM(CONCAT(voornaam, ' ', IFNULL(tussenvoegsel, ''), ' ', achternaam)) = ? AND id != ?");
        $stmt->execute([$fullName, $exclude_id]);
    } else {
        $stmt = $pdo->prepare("SELECT id FROM gebruikers WHERE TRIM(CONCAT(voornaam, ' ', IFNULL(tussenvoegsel, ''), ' ', achternaam)) = ?");
        $stmt->execute([$fullName]);
    }
    $exists = $stmt->fetch() !== false;
    
    if (!$exists && !$exclude_id) {
        $fullNameWithEmptyTussenvoegsel = trim($voornaam . '  ' . $achternaam);
        $stmt = $pdo->prepare("SELECT id FROM gebruikers WHERE TRIM(CONCAT(voornaam, ' ', IFNULL(tussenvoegsel, ''), ' ', achternaam)) = ?");
        $stmt->execute([$fullNameWithEmptyTussenvoegsel]);
        $exists = $stmt->fetch() !== false;
    }
    
    echo json_encode(['exists' => $exists]);
}

function logout() {
    session_destroy();
    echo json_encode(['success' => true]);
}

function checkSession($pdo) {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['loggedIn' => false]);
        return;
    }
    
    echo json_encode([
        'loggedIn' => true,
        'user' => [
            'id' => $_SESSION['user_id'],
            'naam' => $_SESSION['naam'],
            'rol' => $_SESSION['rol'],
            'profielfoto' => $_SESSION['profielfoto'] ?? ''
        ]
    ]);
}

function requireLogin($pdo) {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Niet ingelogd']);
        exit;
    }
}

function requireAdmin($pdo) {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Niet ingelogd']);
        exit;
    }
    
    if ($_SESSION['rol'] !== 'Beheerder') {
        echo json_encode(['error' => 'Geen rechten']);
        exit;
    }
}

function getContentTypes($pdo) {
    $stmt = $pdo->query("SELECT id, naam FROM content_types ORDER BY id");
    $types = $stmt->fetchAll();
    echo json_encode($types);
}

function addContentType($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    $naam = trim($data['naam'] ?? '');
    $omschrijving = $data['omschrijving'] ?? '';
    $afbeelding = $data['afbeelding'] ?? '';
    
    if (!$naam) {
        echo json_encode(['error' => 'Naam is verplicht']);
        return;
    }
    
    $stmt = $pdo->prepare("INSERT INTO content_types (naam, omschrijving, afbeelding) VALUES (?, ?, ?)");
    
    try {
        $stmt->execute([$naam, $omschrijving, $afbeelding]);
        echo json_encode(['success' => true, 'id' => $pdo->lastInsertId()]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function updateContentType($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    $id = $data['id'] ?? 0;
    $naam = trim($data['naam'] ?? '');
    $omschrijving = $data['omschrijving'] ?? '';
    $afbeelding = $data['afbeelding'] ?? '';
    
    if (!$naam || !$id) {
        echo json_encode(['error' => 'Naam is verplicht']);
        return;
    }
    
    $stmt = $pdo->prepare("UPDATE content_types SET naam = ?, omschrijving = ?, afbeelding = ? WHERE id = ?");
    
    try {
        $stmt->execute([$naam, $omschrijving, $afbeelding, $id]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function deleteContentType($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    $id = $data['id'] ?? 0;
    
    if (!$id) {
        echo json_encode(['error' => 'ID is verplicht']);
        return;
    }
    
    $stmt = $pdo->prepare("DELETE FROM content_types WHERE id = ?");
    
    try {
        $stmt->execute([$id]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function getBlogs($pdo) {
    $stmt = $pdo->query("SELECT b.*, g.voornaam, g.achternaam FROM blogposts b LEFT JOIN gebruikers g ON b.auteur_id = g.id ORDER BY b.created_at DESC");
    $blogs = $stmt->fetchAll();
    echo json_encode($blogs);
}

function addBlog($pdo) {
    requireLogin($pdo);
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $titel = trim($data['titel'] ?? '');
    $omschrijving = $data['omschrijving'] ?? '';
    $afbeelding = $data['afbeelding'] ?? '';
    $type_id = $data['type_id'] ?? $data['blogtype_id'] ?? 1;
    $tags = $data['tags'] ?? [];
    $auteur_id = $_SESSION['user_id'] ?? 0;
    
    if (!$titel) {
        echo json_encode(['error' => 'Titel is verplicht']);
        return;
    }
    
    $rol = $_SESSION['rol'];
    $stmt = $pdo->prepare("SELECT permissions FROM rollen WHERE naam = ?");
    $stmt->execute([$rol]);
    $role = $stmt->fetch();
    $perms = $role ? json_decode($role['permissions'], true) : [];
    
    if (!isset($perms[$type_id]['create']) || !$perms[$type_id]['create']) {
        echo json_encode(['error' => 'Geen rechten om een blog te maken in deze categorie']);
        return;
    }
    
    $stmt = $pdo->prepare("INSERT INTO blogposts (titel, omschrijving, afbeelding, auteur_id, content_type_id, tags) VALUES (?, ?, ?, ?, ?, ?)");
    
    try {
        $stmt->execute([$titel, $omschrijving, $afbeelding, $auteur_id, $type_id, json_encode($tags)]);
        echo json_encode(['success' => true, 'id' => $pdo->lastInsertId()]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function updateBlog($pdo) {
    requireLogin($pdo);
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? 0;
    $titel = trim($data['titel'] ?? '');
    $omschrijving = $data['omschrijving'] ?? '';
    $afbeelding = $data['afbeelding'] ?? '';
    $type_id = $data['type_id'] ?? $data['blogtype_id'] ?? 1;
    $tags = $data['tags'] ?? [];
    
    if (!$titel || !$id) {
        echo json_encode(['error' => 'Titel is verplicht']);
        return;
    }
    
    $rol = $_SESSION['rol'];
    $stmt = $pdo->prepare("SELECT permissions FROM rollen WHERE naam = ?");
    $stmt->execute([$rol]);
    $role = $stmt->fetch();
    $perms = $role ? json_decode($role['permissions'], true) : [];
    
    if (!isset($perms[$type_id]['edit']) || !$perms[$type_id]['edit']) {
        echo json_encode(['error' => 'Geen rechten om een blog te wijzigen in deze categorie']);
        return;
    }
    
    $stmt = $pdo->prepare("UPDATE blogposts SET titel = ?, omschrijving = ?, afbeelding = ?, content_type_id = ?, tags = ? WHERE id = ?");
    
    try {
        $stmt->execute([$titel, $omschrijving, $afbeelding, $type_id, json_encode($tags), $id]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function deleteBlog($pdo) {
    requireAdmin($pdo);
    
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? 0;
    
    $stmt = $pdo->prepare("DELETE FROM blogposts WHERE id = ?");
    
    try {
        $stmt->execute([$id]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function uploadImage($pdo = null) {
    header('Content-Type: application/json');
    
    if (!isset($_FILES['image'])) {
        echo json_encode(['error' => 'Geen bestand geüpload']);
        return;
    }
    
    $file = $_FILES['image'];
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    
    if (!in_array($file['type'], $allowedTypes)) {
        echo json_encode(['error' => 'Alleen JPEG, PNG, GIF en WebP toegestaan']);
        return;
    }
    
    if ($file['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['error' => 'Upload fout']);
        return;
    }
    
    $maxWidth = 1920;
    $maxHeight = 1080;
    
    $imageInfo = getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        echo json_encode(['error' => 'Ongeldige afbeelding']);
        return;
    }
    
    $width = $imageInfo[0];
    $height = $imageInfo[1];
    
    $uploadDir = __DIR__ . '/uploads/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }
    
    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
    $filename = uniqid('blog_') . '.' . $extension;
    $targetPath = $uploadDir . $filename;
    
    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        $imageUrl = 'http://localhost/uploads/' . $filename;
        
        if (isset($_SESSION['user_id'])) {
            $userId = $_SESSION['user_id'];
            $stmt = $pdo->prepare("INSERT INTO user_images (user_id, url, filename) VALUES (?, ?, ?)");
            $stmt->execute([$userId, $imageUrl, $file['name']]);
        }
        
        echo json_encode(['success' => true, 'url' => $imageUrl]);
    } else {
        echo json_encode(['error' => 'Kon bestand niet opslaan']);
    }
}

function getUserImages($pdo) {
    $userId = $_SESSION['user_id'] ?? 0;
    
    $stmt = $pdo->prepare("SELECT * FROM user_images WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->execute([$userId]);
    $images = $stmt->fetchAll();
    
    echo json_encode($images);
}

function getUserStats($pdo) {
    $stmt = $pdo->query("SELECT status, COUNT(*) as count FROM gebruikers GROUP BY status");
    $stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $counts = ['pending' => 0, 'active' => 0, 'blocked' => 0];
    foreach ($stats as $row) {
        $counts[$row['status']] = (int)$row['count'];
    }
    
    $total = $counts['pending'] + $counts['active'] + $counts['blocked'];
    
    $result = [
        'total' => $total,
        'pending' => $counts['pending'],
        'active' => $counts['active'],
        'blocked' => $counts['blocked']
    ];
    
    echo json_encode($result);
}

function getPendingUsers($pdo) {
    $stmt = $pdo->query("SELECT id, voornaam, tussenvoegsel, achternaam, emailadres, created_at FROM gebruikers WHERE status = 'pending' ORDER BY created_at DESC");
    $users = $stmt->fetchAll();
    echo json_encode($users);
}

function approveUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? 0;
    $rol = $data['rol'] ?? 'Gebruiker';
    
    if (!$id) {
        echo json_encode(['error' => 'Gebruiker ID is verplicht']);
        return;
    }
    
    $stmt = $pdo->prepare("UPDATE gebruikers SET status = 'active', rol = ? WHERE id = ?");
    
    try {
        $stmt->execute([$rol, $id]);
        
        // Haal gebruiker email op voor notificatie
        $stmt = $pdo->prepare("SELECT emailadres, voornaam FROM gebruikers WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch();
        
        echo json_encode([
            'success' => true, 
            'notify_user' => true,
            'user_email' => $user['emailadres'] ?? '',
            'user_name' => $user['voornaam'] ?? ''
        ]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function rejectUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? 0;
    
    if (!$id) {
        echo json_encode(['error' => 'Gebruiker ID is verplicht']);
        return;
    }
    
    $stmt = $pdo->prepare("DELETE FROM gebruikers WHERE id = ? AND status = 'pending'");
    
    try {
        $stmt->execute([$id]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function blockUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? 0;
    
    if (!$id) {
        echo json_encode(['error' => 'Gebruiker ID is verplicht']);
        return;
    }
    
    $stmt = $pdo->prepare("UPDATE gebruikers SET status = 'blocked' WHERE id = ?");
    
    try {
        $stmt->execute([$id]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function unblockUser($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? 0;
    
    if (!$id) {
        echo json_encode(['error' => 'Gebruiker ID is verplicht']);
        return;
    }
    
    $stmt = $pdo->prepare("UPDATE gebruikers SET status = 'active' WHERE id = ?");
    
    try {
        $stmt->execute([$id]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}
