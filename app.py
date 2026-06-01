from flask import Flask, request, redirect, url_for, render_template, session, jsonify
import psycopg2
import os
from flask_mail import Mail, Message
import secrets
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

# ==============================
# BANCO DE DADOS
# ==============================

DB_HOST = '103.199.186.165'
DB_NAME = 'teste'
DB_USER = 'msconnect'
DB_PASS = 'Ms@2026#123'

# Tempo máximo de inatividade em segundos (2 minutos)
SESSION_TIMEOUT = 120


def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        client_encoding='utf8'
    )
    return conn


# ==============================
# DECORATOR: LOGIN OBRIGATÓRIO
# Protege rotas — usuário sem sessão é bloqueado
# mesmo que tente digitar a URL diretamente
# ==============================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        # Verifica se está logado
        if 'email_usuario' not in session:
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"permitido": False, "mensagem": "Não autenticado.", "redirect": "/"}), 401
            return redirect(url_for('index'))

        # Verifica timeout de inatividade (2 minutos)
        ultima_atividade = session.get('ultima_atividade')
        if ultima_atividade:
            ultima_atividade = datetime.fromisoformat(ultima_atividade)
            if datetime.utcnow() - ultima_atividade > timedelta(seconds=SESSION_TIMEOUT):
                session.clear()
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"permitido": False, "mensagem": "Sessão expirada.", "redirect": "/"}), 401
                return redirect(url_for('index') + '?expirado=1')

        # Atualiza timestamp de última atividade
        session['ultima_atividade'] = datetime.utcnow().isoformat()
        return f(*args, **kwargs)

    return decorated_function


# ==============================
# DECORATOR: PERMISSÃO ADMIN
# Requer permissões: carteira + ligacoes
# ==============================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if 'email_usuario' not in session:
            return redirect(url_for('index'))

        email = session.get('email_usuario')
        conn = get_db_connection()
        cur = conn.cursor()

        # Admin = quem tem AMBAS as permissões: carteira e ligacoes
        cur.execute(
            '''
            SELECT COUNT(DISTINCT dashboard)
            FROM permissoes_dashboard
            WHERE email = %s
            AND dashboard IN ('carteira', 'ligacoes')
            ''',
            (email,)
        )
        resultado = cur.fetchone()
        cur.close()
        conn.close()

        if not resultado or resultado[0] < 2:
            return jsonify({"error": "Acesso negado. Permissão insuficiente."}), 403

        return f(*args, **kwargs)

    return decorated_function


# ==============================
# FUNÇÃO: REGISTRAR AUDITORIA
# Salva log de acesso na tabela auditoria_acessos
# ==============================

def registrar_auditoria(email, nome_usuario, dashboard=None, acao='login'):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Cria tabela se não existir
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS auditoria_acessos (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255),
                nome_usuario VARCHAR(255),
                acao VARCHAR(50),
                dashboard VARCHAR(100),
                ip_address VARCHAR(50),
                data_hora TIMESTAMP DEFAULT NOW()
            )
            '''
        )

        ip = request.remote_addr

        cur.execute(
            '''
            INSERT INTO auditoria_acessos (email, nome_usuario, acao, dashboard, ip_address, data_hora)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ''',
            (email, nome_usuario, acao, dashboard, ip)
        )

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print(f"Erro ao registrar auditoria: {e}")


# ==============================
# HOME
# ==============================

@app.route('/')
def index():
    # Se já está logado, redireciona pro painel
    if 'email_usuario' in session:
        return redirect(url_for('painel'))
    expirado = request.args.get('expirado')
    return render_template('index.html', expirado=expirado)


# ==============================
# CADASTRO
# ==============================

@app.route('/cadastrar', methods=['POST'])
def cadastrar():
    nome  = request.form['nome']
    email = request.form['email']
    senha = request.form['senha']

    if not email.endswith('@msconnect.com.br'):
        return 'Apenas emails corporativos são permitidos.', 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO usuarios (nome, email, senha)
        VALUES (%s, %s, %s)
    """, (nome, email, senha))

    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('index'))


# ==============================
# LOGIN
# ==============================

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    senha = request.form['senha']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, nome, email
        FROM usuarios
        WHERE email = %s AND senha = %s
    """, (email, senha))

    usuario = cur.fetchone()
    cur.close()
    conn.close()

    if usuario:
        session['usuario_id']   = usuario[0]
        session['nome_usuario'] = usuario[1]
        session['email_usuario'] = usuario[2]
        session['ultima_atividade'] = datetime.utcnow().isoformat()

        # Registra login na auditoria
        registrar_auditoria(usuario[2], usuario[1], acao='login')

        return redirect(url_for('painel'))
    else:
        return 'Login inválido'


# ==============================
# PAINEL (PROTEGIDO)
# ==============================

@app.route('/painel')
@login_required
def painel():
    return render_template(
        'painel.html',
        nome_usuario=session.get('nome_usuario')
    )


# ==============================
# VALIDAÇÃO DE PERMISSÃO (PROTEGIDA)
# ==============================

@app.route('/validar-dashboard/<dashboard>')
@login_required
def validar_dashboard(dashboard):
    email        = session.get('email_usuario')
    nome_usuario = session.get('nome_usuario')

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id
        FROM permissoes_dashboard
        WHERE email = %s
        AND dashboard = %s
    """, (email, dashboard))

    permissao = cur.fetchone()
    cur.close()
    conn.close()

    if permissao:
        # Registra acesso ao dashboard na auditoria
        registrar_auditoria(email, nome_usuario, dashboard=dashboard, acao='acesso_dashboard')
        return jsonify({"permitido": True})
    else:
        return jsonify({
            "permitido": False,
            "mensagem": "Você não possui permissão para acessar este dashboard."
        })


# ==============================
# RELATÓRIOS DE AUDITORIA (SOMENTE ADMIN)
# Requer permissões: carteira + ligacoes
# ==============================

@app.route('/relatorios-dados')
@login_required
@admin_required
def relatorios_dados():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        '''
        SELECT nome_usuario, email, acao, dashboard, ip_address,
               TO_CHAR(data_hora AT TIME ZONE 'America/Cuiaba', 'DD/MM/YYYY HH24:MI:SS') as data_hora_fmt
        FROM auditoria_acessos
        ORDER BY data_hora DESC
        LIMIT 200
        '''
    )

    rows = cur.fetchall()
    cur.close()
    conn.close()

    registros = []
    for row in rows:
        registros.append({
            "nome_usuario": row[0],
            "email":        row[1],
            "acao":         row[2],
            "dashboard":    row[3] or "-",
            "ip_address":   row[4],
            "data_hora":    row[5]
        })

    return jsonify(registros)


# ==============================
# VERIFICAR PERMISSÃO ADMIN
# (frontend usa para exibir/ocultar menu de Relatórios)
# ==============================

@app.route('/verificar-admin')
@login_required
def verificar_admin():
    email = session.get('email_usuario')
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        '''
        SELECT COUNT(DISTINCT dashboard)
        FROM permissoes_dashboard
        WHERE email = %s
        AND dashboard IN ('carteira', 'ligacoes')
        ''',
        (email,)
    )
    resultado = cur.fetchone()
    cur.close()
    conn.close()

    is_admin = resultado and resultado[0] >= 2
    return jsonify({"is_admin": bool(is_admin)})


# ==============================
# PING DE ATIVIDADE
# (frontend envia a cada 30s enquanto o usuário está ativo)
# ==============================

@app.route('/ping-atividade', methods=['POST'])
@login_required
def ping_atividade():
    # O decorator já atualiza ultima_atividade
    return jsonify({"ok": True})


# ==============================
# VERIFICAR SESSÃO
# (frontend checa periodicamente se ainda está logado)
# ==============================

@app.route('/verificar-sessao')
def verificar_sessao():
    if 'email_usuario' not in session:
        return jsonify({"logado": False})

    ultima_atividade = session.get('ultima_atividade')
    if ultima_atividade:
        ultima_atividade = datetime.fromisoformat(ultima_atividade)
        if datetime.utcnow() - ultima_atividade > timedelta(seconds=SESSION_TIMEOUT):
            session.clear()
            return jsonify({"logado": False, "motivo": "timeout"})

    return jsonify({"logado": True})


# ==============================
# LOGOUT
# ==============================

@app.route('/logout')
def logout():
    email        = session.get('email_usuario')
    nome_usuario = session.get('nome_usuario')

    if email:
        registrar_auditoria(email, nome_usuario, acao='logout')

    session.clear()
    return redirect(url_for('index'))


# ==============================
# RESET DE SENHA
# ==============================

app.config['MAIL_SERVER']   = 'smtp.gmail.com'
app.config['MAIL_PORT']     = 587
app.config['MAIL_USE_TLS']  = True
app.config['MAIL_USERNAME'] = 'seu_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'sua_senha_do_email'

mail = Mail(app)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        usuario = cur.fetchone()
        cur.close()
        conn.close()

        if usuario:
            token = secrets.token_hex(16)

            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE usuarios SET reset_token = %s WHERE email = %s", (token, email))
            conn.commit()
            cur.close()
            conn.close()

            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message(
                'Redefinição de Senha',
                sender='seu_email@gmail.com',
                recipients=[email]
            )
            msg.body = f'Clique no link para redefinir sua senha: {reset_link}'
            mail.send(msg)

            return 'Um e-mail foi enviado com instruções para redefinir sua senha.'

        return 'E-mail não encontrado.'

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM usuarios WHERE reset_token = %s", (token,))
    usuario = cur.fetchone()
    cur.close()
    conn.close()

    if not usuario:
        return 'Token inválido ou expirado.'

    if request.method == 'POST':
        nova_senha = request.form['nova_senha']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE usuarios SET senha = %s, reset_token = NULL WHERE reset_token = %s",
            (nova_senha, token)
        )
        conn.commit()
        cur.close()
        conn.close()

        return 'Sua senha foi redefinida com sucesso!'

    return render_template('reset_password.html', token=token)


# ==============================
# START FLASK
# ==============================

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)