from flask import Flask, request, jsonify
import sqlite3
from functools import wraps
import uuid
import time
from datetime import datetime, timedelta

app = Flask(__name__)
sessions = {}  # Estructura: {token: {"username": str, "expires": timestamp}}
admin_users = {"admin"}
TOKEN_LIFETIME = 300  # 5 minutos en segundos

def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Tabla de usuarios
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            birthdate TEXT,
            status TEXT DEFAULT 'active',
            secret_question TEXT,
            secret_answer TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Tabla de roles
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            description TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    # Tabla de permisos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            description TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    # Tabla de asignación usuario-rol
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER,
            role_id INTEGER,
            assigned_by INTEGER,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(user_id, role_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(role_id) REFERENCES roles(id),
            FOREIGN KEY(assigned_by) REFERENCES users(id)
        )
    """)

    # Tabla de asignación rol-permiso
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER,
            permission_id INTEGER,
            assigned_by INTEGER,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(role_id, permission_id),
            FOREIGN KEY(role_id) REFERENCES roles(id),
            FOREIGN KEY(permission_id) REFERENCES permissions(id),
            FOREIGN KEY(assigned_by) REFERENCES users(id)
        )
    """)

    # Insertar usuario admin por defecto
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, birthdate, secret_question, secret_answer)
        VALUES ('admin', '1234', 'admin@localhost', '2000-01-01', '¿Cual es tu mascota?', 'tiburon')
    """)

    # Insertar permisos básicos
    basic_permissions = [
        'get_user', 'create_user', 'update_user', 'delete_user',
        'get_product', 'create_product', 'update_product', 'delete_product',
        'get_role', 'create_role', 'update_role', 'delete_role',
        'get_permission', 'create_permission', 'update_permission', 'delete_permission'
    ]
    
    for perm in basic_permissions:
        cursor.execute("INSERT OR IGNORE INTO permissions (name, description) VALUES (?, ?)", 
                      (perm, f"Permiso para {perm}"))

    # Insertar roles básicos
    cursor.execute("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", 
                  ('admin', 'Administrador del sistema'))
    cursor.execute("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", 
                  ('common_user', 'Usuario común'))
    cursor.execute("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", 
                  ('seller', 'Vendedor'))

    conn.commit()
    conn.close()

def clean_expired_sessions():
    """Limpia las sesiones expiradas"""
    current_time = time.time()
    expired_tokens = [token for token, data in sessions.items() if data["expires"] < current_time]
    for token in expired_tokens:
        del sessions[token]

# Decorador de autenticación con token temporal
def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        clean_expired_sessions()
        
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token faltante"}), 401
            
        if token not in sessions:
            return jsonify({"error": "Token inválido"}), 401
            
        session_data = sessions[token]
        if session_data["expires"] < time.time():
            del sessions[token]
            return jsonify({"error": "Token expirado"}), 401
            
        username = session_data["username"]
        return f(username, *args, **kwargs)
    return decorated

# Decorador de verificación de admin
def require_admin(f):
    @wraps(f)
    def decorated(username, *args, **kwargs):
        if username not in admin_users:
            return jsonify({"error": "Permisos insuficientes"}), 403
        return f(username, *args, **kwargs)
    return decorated

def get_user_id(username):
    """Obtiene el ID del usuario por username"""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# Registro de usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    required = ["username", "password", "email", "birthdate", "secret_question", "secret_answer"]
    if not all(k in data for k in required):
        return jsonify({"error": "Faltan campos"}), 400

    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password, email, birthdate, secret_question, secret_answer)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (data["username"], data["password"], data["email"], data["birthdate"],
              data["secret_question"], data["secret_answer"]))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Usuario ya existe"}), 409
    finally:
        conn.close()

    return jsonify({"message": "Usuario registrado exitosamente"})

# Login de usuario
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username y password requeridos"}), 400
        
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ? AND status = 'active'", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        token = str(uuid.uuid4())
        expires = time.time() + TOKEN_LIFETIME
        sessions[token] = {
            "username": username,
            "expires": expires
        }
        
        expires_datetime = datetime.fromtimestamp(expires)
        return jsonify({
            "message": "Login exitoso", 
            "token": token,
            "expires_at": expires_datetime.isoformat(),
            "expires_in_seconds": TOKEN_LIFETIME
        })
    return jsonify({"error": "Credenciales inválidas"}), 401

# Logout
@app.route('/logout', methods=['POST'])
@require_token
def logout(username):
    token = request.headers.get("Authorization")
    if token in sessions:
        del sessions[token]
    return jsonify({"message": "Logout exitoso"})

# Renovar token
@app.route('/refresh-token', methods=['POST'])
@require_token
def refresh_token(username):
    token = request.headers.get("Authorization")
    if token in sessions:
        sessions[token]["expires"] = time.time() + TOKEN_LIFETIME
        expires_datetime = datetime.fromtimestamp(sessions[token]["expires"])
        return jsonify({
            "message": "Token renovado",
            "expires_at": expires_datetime.isoformat(),
            "expires_in_seconds": TOKEN_LIFETIME
        })
    return jsonify({"error": "Token no encontrado"}), 404

# CRUD de Permisos
@app.route('/permissions', methods=['POST'])
@require_token
@require_admin
def create_permission(username):
    data = request.json
    name = data.get("name")
    description = data.get("description", "")
    
    if not name:
        return jsonify({"error": "Nombre requerido"}), 400
        
    user_id = get_user_id(username)
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO permissions (name, description, created_by) VALUES (?, ?, ?)", 
                      (name, description, user_id))
        permission_id = cursor.lastrowid
        conn.commit()
        return jsonify({
            "message": "Permiso creado exitosamente", 
            "id": permission_id,
            "name": name,
            "description": description
        })
    except sqlite3.IntegrityError:
        return jsonify({"error": "Permiso ya existe"}), 409
    finally:
        conn.close()

@app.route('/permissions', methods=['GET'])
@require_token
def list_permissions(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.id, p.name, p.description, u.username as created_by, p.created_at 
        FROM permissions p 
        LEFT JOIN users u ON p.created_by = u.id
    """)
    perms = cursor.fetchall()
    conn.close()
    
    return jsonify([{
        "id": p[0], 
        "name": p[1], 
        "description": p[2],
        "created_by": p[3],
        "created_at": p[4]
    } for p in perms])

@app.route('/permissions/<int:perm_id>', methods=['GET'])
@require_token
def get_permission(username, perm_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.id, p.name, p.description, u.username as created_by, p.created_at 
        FROM permissions p 
        LEFT JOIN users u ON p.created_by = u.id
        WHERE p.id = ?
    """, (perm_id,))
    perm = cursor.fetchone()
    conn.close()
    
    if not perm:
        return jsonify({"error": "Permiso no encontrado"}), 404
        
    return jsonify({
        "id": perm[0],
        "name": perm[1],
        "description": perm[2],
        "created_by": perm[3],
        "created_at": perm[4]
    })

@app.route('/permissions/<int:perm_id>', methods=['PUT'])
@require_token
@require_admin
def update_permission(username, perm_id):
    data = request.json
    name = data.get("name")
    description = data.get("description")
    
    if not name:
        return jsonify({"error": "Nombre requerido"}), 400
        
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE permissions SET name = ?, description = ? WHERE id = ?", 
                  (name, description, perm_id))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"error": "Permiso no encontrado"}), 404
        
    conn.commit()
    conn.close()
    return jsonify({"message": "Permiso actualizado exitosamente"})

@app.route('/permissions/<int:perm_id>', methods=['DELETE'])
@require_token
@require_admin
def delete_permission(username, perm_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM permissions WHERE id = ?", (perm_id,))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"error": "Permiso no encontrado"}), 404
        
    conn.commit()
    conn.close()
    return jsonify({"message": "Permiso eliminado exitosamente"})

# CRUD de Roles
@app.route('/roles', methods=['POST'])
@require_token
@require_admin
def create_role(username):
    data = request.json
    name = data.get("name")
    description = data.get("description", "")
    permission_ids = data.get("permissions", [])
    
    if not name:
        return jsonify({"error": "Nombre requerido"}), 400
        
    user_id = get_user_id(username)
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        
        # Crear el rol
        cursor.execute("INSERT INTO roles (name, description, created_by) VALUES (?, ?, ?)", 
                      (name, description, user_id))
        role_id = cursor.lastrowid
        
        # Asignar permisos al rol
        for perm_id in permission_ids:
            cursor.execute("INSERT INTO role_permissions (role_id, permission_id, assigned_by) VALUES (?, ?, ?)", 
                          (role_id, perm_id, user_id))
        
        conn.commit()
        return jsonify({
            "message": "Rol creado exitosamente", 
            "id": role_id,
            "name": name,
            "description": description,
            "permissions": permission_ids
        })
    except sqlite3.IntegrityError:
        return jsonify({"error": "Rol ya existe"}), 409
    finally:
        conn.close()

@app.route('/roles', methods=['GET'])
@require_token
def list_roles(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.id, r.name, r.description, u.username as created_by, r.created_at 
        FROM roles r 
        LEFT JOIN users u ON r.created_by = u.id
    """)
    roles = cursor.fetchall()
    
    # Obtener permisos para cada rol
    result = []
    for role in roles:
        cursor.execute("""
            SELECT p.id, p.name FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ?
        """, (role[0],))
        permissions = cursor.fetchall()
        
        result.append({
            "id": role[0],
            "name": role[1],
            "description": role[2],
            "created_by": role[3],
            "created_at": role[4],
            "permissions": [{"id": p[0], "name": p[1]} for p in permissions]
        })
    
    conn.close()
    return jsonify(result)

@app.route('/roles/<int:role_id>', methods=['GET'])
@require_token
def get_role(username, role_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.id, r.name, r.description, u.username as created_by, r.created_at 
        FROM roles r 
        LEFT JOIN users u ON r.created_by = u.id
        WHERE r.id = ?
    """, (role_id,))
    role = cursor.fetchone()
    
    if not role:
        conn.close()
        return jsonify({"error": "Rol no encontrado"}), 404
    
    # Obtener permisos del rol
    cursor.execute("""
        SELECT p.id, p.name FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
    """, (role_id,))
    permissions = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        "id": role[0],
        "name": role[1],
        "description": role[2],
        "created_by": role[3],
        "created_at": role[4],
        "permissions": [{"id": p[0], "name": p[1]} for p in permissions]
    })

@app.route('/roles/<int:role_id>', methods=['PUT'])
@require_token
@require_admin
def update_role(username, role_id):
    data = request.json
    name = data.get("name")
    description = data.get("description")
    permission_ids = data.get("permissions", [])
    
    if not name:
        return jsonify({"error": "Nombre requerido"}), 400
        
    user_id = get_user_id(username)
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    
    # Verificar que el rol existe
    cursor.execute("SELECT id FROM roles WHERE id = ?", (role_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Rol no encontrado"}), 404
    
    # Actualizar rol
    cursor.execute("UPDATE roles SET name = ?, description = ? WHERE id = ?", 
                  (name, description, role_id))
    
    # Eliminar permisos existentes del rol
    cursor.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
    
    # Asignar nuevos permisos
    for perm_id in permission_ids:
        cursor.execute("INSERT INTO role_permissions (role_id, permission_id, assigned_by) VALUES (?, ?, ?)", 
                      (role_id, perm_id, user_id))
    
    conn.commit()
    conn.close()
    return jsonify({"message": "Rol actualizado exitosamente"})

@app.route('/roles/<int:role_id>', methods=['DELETE'])
@require_token
@require_admin
def delete_role(username, role_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM roles WHERE id = ?", (role_id,))
    
    if cursor.rowcount == 0:
        conn.close()
        return jsonify({"error": "Rol no encontrado"}), 404
        
    conn.commit()
    conn.close()
    return jsonify({"message": "Rol eliminado exitosamente"})

# Asignar rol a usuario
@app.route('/users/<int:user_id>/roles', methods=['POST'])
@require_token
@require_admin
def assign_role_to_user(username, user_id):
    data = request.json
    role_id = data.get("role_id")
    
    if not role_id:
        return jsonify({"error": "role_id requerido"}), 400
        
    assigned_by = get_user_id(username)
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)", 
                      (user_id, role_id, assigned_by))
        conn.commit()
        return jsonify({"message": "Rol asignado al usuario exitosamente"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "El usuario ya tiene este rol"}), 409
    finally:
        conn.close()

# Ver usuarios con sus roles
@app.route('/users', methods=['GET'])
@require_token
@require_admin
def get_all_users(username):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, birthdate, status, created_at FROM users")
    users = cursor.fetchall()
    
    result = []
    for user in users:
        # Obtener roles del usuario
        cursor.execute("""
            SELECT r.id, r.name FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = ?
        """, (user[0],))
        roles = cursor.fetchall()
        
        result.append({
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "birthdate": user[3],
            "status": user[4],
            "created_at": user[5],
            "roles": [{"id": r[0], "name": r[1]} for r in roles]
        })
    
    conn.close()
    return jsonify(result)

# Estado de la sesión
@app.route('/session/status', methods=['GET'])
@require_token
def session_status(username):
    token = request.headers.get("Authorization")
    session_data = sessions.get(token)
    
    if session_data:
        remaining_time = max(0, session_data["expires"] - time.time())
        return jsonify({
            "username": username,
            "expires_at": datetime.fromtimestamp(session_data["expires"]).isoformat(),
            "remaining_seconds": int(remaining_time),
            "is_active": remaining_time > 0
        })
    
    return jsonify({"error": "Sesión no encontrada"}), 404

if __name__ == '__main__':
    init_db()
    app.run(debug=True)