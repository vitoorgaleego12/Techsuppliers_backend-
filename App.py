import os, sqlite3, re, html, secrets, logging
from flask import Flask, request, jsonify, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from collections import defaultdict
from time import time

# ==============================
# Configurações iniciais
# ==============================
app = Flask(__name__, static_folder="static")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PASTA_PROJETO = os.path.dirname(os.path.abspath(__file__))
CAMINHO_BANCO_FORNECEDORES = os.path.join(PASTA_PROJETO, "fornecedores.db")
CAMINHO_BANCO_CLIENTES = os.path.join(PASTA_PROJETO, "clientes.db")

# Rate limiting (simples)
request_times = defaultdict(list)

def rate_limit(max_requests=100, window=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr
            now = time()
            request_times[ip] = [t for t in request_times[ip] if now - t < window]
            if len(request_times[ip]) >= max_requests:
                return jsonify({"status": "erro","mensagem":"Muitas requisições"}), 429
            request_times[ip].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator

# ==============================
# Funções de sanitização e validação
# ==============================
def sanitizar(texto):
    if not texto: return ""
    texto = str(texto).strip()
    texto = html.escape(texto)
    texto = re.sub(r'[;\"\']', '', texto)
    return texto

def validar_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email) is not None

def validar_cpf(cpf):
    cpf = re.sub(r'\D', '', cpf)
    if len(cpf) != 11 or cpf == cpf[0]*11: return False
    for i in range(9,11):
        soma = sum(int(cpf[j])*((i+1)-j) for j in range(i))
        digito = 11 - (soma % 11)
        if digito > 9: digito=0
        if digito != int(cpf[i]): return False
    return True

def validar_telefone(tel):
    tel = re.sub(r'\D','',tel)
    return len(tel) in [10,11]

# ==============================
# Conexão com SQLite
# ==============================
def get_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def criar_bancos():
    # Fornecedores
    conn = get_db(CAMINHO_BANCO_FORNECEDORES)
    conn.execute('''CREATE TABLE IF NOT EXISTS fornecedores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT, razao TEXT, cpfcnpj TEXT UNIQUE, idade INTEGER,
        telefone TEXT, email TEXT, endereco TEXT, site TEXT,
        servico TEXT, tempo TEXT, contrato TEXT, responsavel TEXT, obs TEXT,
        data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit(); conn.close()
    # Clientes
    conn = get_db(CAMINHO_BANCO_CLIENTES)
    conn.execute('''CREATE TABLE IF NOT EXISTS clientes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT, idade INTEGER, email TEXT UNIQUE, telefone TEXT,
        endereco TEXT, genero TEXT, cpf TEXT UNIQUE, senha TEXT,
        data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit(); conn.close()

criar_bancos()

# ==============================
# Endpoints de cadastro
# ==============================
@app.route('/cadastrar_cliente', methods=['POST'])
@rate_limit(10,60)
def cadastrar_cliente():
    nome = sanitizar(request.form.get('nome'))
    idade = request.form.get('idade')
    email = sanitizar(request.form.get('email'))
    telefone = sanitizar(request.form.get('telefone'))
    endereco = sanitizar(request.form.get('endereco'))
    genero = sanitizar(request.form.get('genero'))
    cpf = sanitizar(request.form.get('cpf'))
    senha = request.form.get('senha')

    # validações
    if not all([nome, idade, email, telefone, endereco, genero, cpf, senha]):
        return jsonify({"status":"erro","mensagem":"Todos os campos são obrigatórios"}),400
    if not validar_email(email): return jsonify({"status":"erro","mensagem":"Email inválido"}),400
    if not validar_telefone(telefone): return jsonify({"status":"erro","mensagem":"Telefone inválido"}),400
    if not validar_cpf(cpf): return jsonify({"status":"erro","mensagem":"CPF inválido"}),400

    # inserir
    senha_hash = generate_password_hash(senha)
    conn = get_db(CAMINHO_BANCO_CLIENTES)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM clientes WHERE email=? OR cpf=?", (email,cpf))
    if cursor.fetchone(): return jsonify({"status":"erro","mensagem":"Email ou CPF já cadastrado"}),400
    cursor.execute('''INSERT INTO clientes (nome, idade, email, telefone, endereco, genero, cpf, senha)
                      VALUES (?,?,?,?,?,?,?,?)''',
                   (nome,int(idade),email,telefone,endereco,genero,cpf,senha_hash))
    conn.commit(); conn.close()
    return jsonify({"status":"ok","mensagem":"Cliente cadastrado com sucesso"})

# ==============================
# Endpoint listar clientes (JSON)
# ==============================
@app.route('/clientes_json')
@rate_limit(30,60)
def clientes_json():
    conn = get_db(CAMINHO_BANCO_CLIENTES)
    cursor = conn.cursor()
    cursor.execute("SELECT id,nome,email,telefone,cpf,genero FROM clientes ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ==============================
# Login simples
# ==============================
@app.route('/login_cliente', methods=['POST'])
@rate_limit(10,60)
def login_cliente():
    email = sanitizar(request.form.get('email'))
    senha = request.form.get('senha')
    conn = get_db(CAMINHO_BANCO_CLIENTES)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM clientes WHERE email=?", (email,))
    cliente = cursor.fetchone(); conn.close()
    if not cliente or not check_password_hash(cliente['senha'],senha):
        return jsonify({"status":"erro","mensagem":"Email ou senha incorretos"}),401
    session['cliente_id']=cliente['id']
    session['cliente_nome']=cliente['nome']
    return jsonify({"status":"ok","mensagem":"Login realizado com sucesso"})

# ==============================
# Servir frontend estático (apenas HTML/CSS/JS)
# ==============================
@app.route('/')
def index():
    return send_from_directory(os.path.join(PASTA_PROJETO,'../frontend'),'index.html')

@app.route('/<path:filename>')
def serve_page(filename):
    return send_from_directory(os.path.join(PASTA_PROJETO,'../frontend'), filename)

# ==============================
if __name__=="__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=True)
