#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sistema de Helpdesk TI - Com Gerenciamento Completo de Usuários"""

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import os
import json
import secrets

# Configuração do caminho do banco de dados
base_dir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.join(base_dir, 'instance')
if not os.path.exists(instance_dir):
    os.makedirs(instance_dir)
db_path = os.path.join(instance_dir, 'helpdesk.db')

# Criar aplicação Flask
app = Flask(__name__)

# CONFIGURAÇÕES IMPORTANTES
app.config['SECRET_KEY'] = 'helpdesk-secret-key-mudar-em-producao-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path.replace('\\', '/')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Inicializar extensões
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'info'

# ==================== DECORADORES ====================

def admin_required(f):
    """Decorador que requer que o usuário seja admin"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Acesso negado. Apenas administradores.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def active_required(f):
    """Decorador que requer que o usuário esteja ativo"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and not current_user.is_active:
            flash('Sua conta foi desativada. Entre em contato com o administrador.', 'warning')
            logout_user()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== MODELOS ====================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')  # admin, technician, user
    department = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    last_login = db.Column(db.DateTime)
    
    # Gamificação
    points = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    badges = db.Column(db.Text, default='[]')
    streak_days = db.Column(db.Integer, default=0)
    
    # Relacionamentos
    creator = db.relationship('User', remote_side=[id], backref='created_users')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def add_points(self, points):
        self.points += points
        self.level = (self.points // 100) + 1
        db.session.commit()
    
    def get_badges(self):
        try:
            return json.loads(self.badges) if self.badges else []
        except:
            return []
    
    def can_view_ticket(self, ticket):
        """Verifica se o usuário pode ver um ticket"""
        if self.role in ['admin', 'technician']:
            return True
        return ticket.user_id == self.id
    
    def can_edit_ticket(self, ticket):
        """Verifica se o usuário pode editar um ticket"""
        if self.role == 'admin':
            return True
        if self.role == 'technician' and ticket.assigned_to == self.id:
            return True
        return False
    
    @property
    def tickets_count(self):
        return Ticket.query.filter_by(user_id=self.id).count()
    
    @property
    def open_tickets_count(self):
        return Ticket.query.filter_by(user_id=self.id, status='open').count()

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='open')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolution_time = db.Column(db.Integer)  # em minutos
    
    creator = db.relationship('User', foreign_keys=[user_id], backref='tickets_created')
    technician = db.relationship('User', foreign_keys=[assigned_to], backref='tickets_assigned')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_internal = db.Column(db.Boolean, default=False)  # Comentários internos só para técnicos/admin
    
    ticket = db.relationship('Ticket', backref='comments')
    author = db.relationship('User', backref='comments')

# ==================== FORMULÁRIOS ====================

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(message='Campo obrigatório')])
    password = PasswordField('Senha', validators=[DataRequired(message='Campo obrigatório')])
    remember = BooleanField('Lembrar-me')

class UserCreateForm(FlaskForm):
    """Formulário para admin criar usuários"""
    username = StringField('Nome de Usuário', validators=[
        DataRequired(message='Campo obrigatório'),
        Length(min=3, max=80, message='Entre 3 e 80 caracteres')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Campo obrigatório'),
        Email(message='Email inválido')
    ])
    full_name = StringField('Nome Completo', validators=[
        DataRequired(message='Campo obrigatório')
    ])
    department = StringField('Departamento', validators=[
        DataRequired(message='Campo obrigatório')
    ])
    role = SelectField('Função', choices=[
        ('user', 'Usuário'),
        ('technician', 'Técnico'),
        ('admin', 'Administrador')
    ], default='user')
    password = PasswordField('Senha Inicial', validators=[
        DataRequired(message='Campo obrigatório'),
        Length(min=6, message='Mínimo de 6 caracteres')
    ])
    send_credentials = BooleanField('Enviar credenciais por email (simulado)')

class UserEditForm(FlaskForm):
    """Formulário para editar usuários"""
    email = StringField('Email', validators=[
        DataRequired(message='Campo obrigatório'),
        Email(message='Email inválido')
    ])
    full_name = StringField('Nome Completo', validators=[
        DataRequired(message='Campo obrigatório')
    ])
    department = StringField('Departamento', validators=[
        DataRequired(message='Campo obrigatório')
    ])
    role = SelectField('Função', choices=[
        ('user', 'Usuário'),
        ('technician', 'Técnico'),
        ('admin', 'Administrador')
    ])
    is_active = BooleanField('Conta Ativa')

class PasswordResetForm(FlaskForm):
    """Formulário para resetar senha"""
    new_password = PasswordField('Nova Senha', validators=[
        DataRequired(message='Campo obrigatório'),
        Length(min=6, message='Mínimo de 6 caracteres')
    ])
    confirm_password = PasswordField('Confirmar Nova Senha', validators=[
        DataRequired(message='Campo obrigatório'),
        EqualTo('new_password', message='As senhas devem ser iguais')
    ])

class TicketForm(FlaskForm):
    title = StringField('Título', validators=[DataRequired(message='Campo obrigatório')])
    description = TextAreaField('Descrição', validators=[DataRequired(message='Campo obrigatório')])
    category = SelectField('Categoria', choices=[
        ('hardware', 'Hardware'),
        ('software', 'Software'),
        ('network', 'Rede'),
        ('printer', 'Impressora'),
        ('email', 'Email'),
        ('access', 'Acesso/Permissões'),
        ('other', 'Outros')
    ])
    priority = SelectField('Prioridade', choices=[
        ('low', 'Baixa'),
        ('medium', 'Média'),
        ('high', 'Alta'),
        ('critical', 'Crítica')
    ])

class CommentForm(FlaskForm):
    content = TextAreaField('Comentário', validators=[DataRequired()])
    is_internal = BooleanField('Comentário interno (apenas técnicos/admin)')

# ==================== LOGIN MANAGER ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== FILTROS E CONTEXTO ====================

@app.template_filter('priority_color')
def priority_color(priority):
    colors = {
        'low': 'success',
        'medium': 'warning', 
        'high': 'danger',
        'critical': 'dark'
    }
    return colors.get(priority, 'secondary')

@app.template_filter('status_color')
def status_color(status):
    colors = {
        'open': 'info',
        'in_progress': 'warning',
        'resolved': 'success',
        'closed': 'secondary'
    }
    return colors.get(status, 'secondary')

@app.context_processor
def inject_globals():
    return {
        'category_icons': {
            'hardware': 'fa-desktop',
            'software': 'fa-code',
            'network': 'fa-network-wired',
            'printer': 'fa-print',
            'email': 'fa-envelope',
            'access': 'fa-key',
            'other': 'fa-question-circle'
        }
    }

# ==================== ROTAS DE AUTENTICAÇÃO ====================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Sua conta foi desativada. Entre em contato com o administrador.', 'warning')
                return render_template('auth/login.html', form=form)
            
            login_user(user, remember=form.remember.data)
            user.last_login = datetime.utcnow()
            # Pontos apenas para técnicos/admin
            if user.role in ['admin', 'technician']:
                user.add_points(5)  # Pontos por login
            db.session.commit()
            
            flash(f'Bem-vindo, {user.full_name}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        
        flash('Usuário ou senha incorretos', 'danger')
    
    return render_template('auth/login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso!', 'info')
    return redirect(url_for('login'))

# ==================== ROTAS DE DASHBOARD ====================

@app.route('/dashboard')
@login_required
@active_required
def dashboard():
    # Estatísticas baseadas no role do usuário
    if current_user.role in ['admin', 'technician']:
        total_tickets = Ticket.query.count()
        open_tickets = Ticket.query.filter_by(status='open').count()
        in_progress = Ticket.query.filter_by(status='in_progress').count()
        resolved = Ticket.query.filter_by(status='resolved').count()
        
        my_tickets = Ticket.query.filter_by(assigned_to=current_user.id).limit(5).all()
        recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(10).all()
        
        # Estatísticas de usuários (só para admin)
        total_users = User.query.count() if current_user.role == 'admin' else 0
        active_users = User.query.filter_by(is_active=True).count() if current_user.role == 'admin' else 0
    else:
        # Usuário normal vê apenas seus tickets
        total_tickets = Ticket.query.filter_by(user_id=current_user.id).count()
        open_tickets = Ticket.query.filter_by(user_id=current_user.id, status='open').count()
        in_progress = Ticket.query.filter_by(user_id=current_user.id, status='in_progress').count()
        resolved = Ticket.query.filter_by(user_id=current_user.id, status='resolved').count()
        
        my_tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).limit(5).all()
        recent_tickets = my_tickets
        
        total_users = 0
        active_users = 0
    
    stats = {
        'total': total_tickets,
        'open': open_tickets,
        'in_progress': in_progress,
        'resolved': resolved,
        'total_users': total_users,
        'active_users': active_users
    }
    
    # Top técnicos/admin (gamificação - apenas quem resolve tickets)
    top_users = User.query.filter(
        User.is_active == True,
        User.role.in_(['admin', 'technician'])
    ).order_by(User.points.desc()).limit(5).all()
    
    return render_template('dashboard/index.html',
                         stats=stats,
                         my_tickets=my_tickets,
                         recent_tickets=recent_tickets,
                         top_users=top_users)

# ==================== ROTAS DE GERENCIAMENTO DE USUÁRIOS (ADMIN) ====================

@app.route('/admin/users')
@admin_required
def admin_users():
    """Lista todos os usuários - Apenas Admin"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    
    query = User.query
    
    if search:
        query = query.filter(
            db.or_(
                User.username.contains(search),
                User.email.contains(search),
                User.full_name.contains(search)
            )
        )
    
    users = query.order_by(User.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    
    return render_template('admin/users.html', users=users, search=search)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    """Criar novo usuário - Apenas Admin"""
    form = UserCreateForm()
    
    if form.validate_on_submit():
        # Verifica se usuário já existe
        if User.query.filter_by(username=form.username.data).first():
            flash('Nome de usuário já existe!', 'danger')
            return render_template('admin/create_user.html', form=form)
        
        if User.query.filter_by(email=form.email.data).first():
            flash('Email já cadastrado!', 'danger')
            return render_template('admin/create_user.html', form=form)
        
        # Cria novo usuário
        user = User(
            username=form.username.data,
            email=form.email.data,
            full_name=form.full_name.data,
            department=form.department.data,
            role=form.role.data,
            created_by=current_user.id
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        # Simula envio de email
        if form.send_credentials.data:
            flash(f'Usuário criado! Credenciais "enviadas" para {form.email.data}', 'success')
            flash(f'Login: {form.username.data} | Senha: {form.password.data}', 'info')
        else:
            flash('Usuário criado com sucesso!', 'success')
        
        return redirect(url_for('admin_users'))
    
    return render_template('admin/create_user.html', form=form)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    """Editar usuário - Apenas Admin"""
    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user)
    
    if form.validate_on_submit():
        # Verifica email duplicado
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user and existing_user.id != user_id:
            flash('Email já está em uso!', 'danger')
            return render_template('admin/edit_user.html', form=form, user=user)
        
        user.email = form.email.data
        user.full_name = form.full_name.data
        user.department = form.department.data
        user.role = form.role.data
        user.is_active = form.is_active.data
        
        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/edit_user.html', form=form, user=user)

@app.route('/admin/users/<int:user_id>/reset-password', methods=['GET', 'POST'])
@admin_required
def admin_reset_password(user_id):
    """Resetar senha de usuário - Apenas Admin"""
    user = User.query.get_or_404(user_id)
    form = PasswordResetForm()
    
    if form.validate_on_submit():
        user.set_password(form.new_password.data)
        db.session.commit()
        
        flash(f'Senha de {user.username} resetada com sucesso!', 'success')
        flash(f'Nova senha: {form.new_password.data}', 'info')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/reset_password.html', form=form, user=user)

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def admin_toggle_user_status(user_id):
    """Ativar/Desativar usuário - Apenas Admin"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Você não pode desativar sua própria conta!', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'ativado' if user.is_active else 'desativado'
    flash(f'Usuário {user.username} foi {status}!', 'success')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Deletar usuário - Apenas Admin"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Você não pode deletar sua própria conta!', 'danger')
        return redirect(url_for('admin_users'))
    
    # Verifica se o usuário tem tickets
    if user.tickets_count > 0:
        flash('Não é possível deletar usuário com tickets. Desative a conta ao invés disso.', 'warning')
        return redirect(url_for('admin_users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'Usuário {username} foi deletado permanentemente!', 'success')
    return redirect(url_for('admin_users'))

# ==================== ROTAS DE TICKETS ====================

@app.route('/tickets')
@login_required
@active_required
def tickets_list():
    """Lista de tickets - Usuários veem apenas seus tickets"""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    
    # Query base dependendo do role
    if current_user.role in ['admin', 'technician']:
        query = Ticket.query
    else:
        # Usuários normais veem apenas seus tickets
        query = Ticket.query.filter_by(user_id=current_user.id)
    
    # Filtro de status
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    tickets = query.order_by(Ticket.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    return render_template('tickets/list.html', tickets=tickets, status_filter=status_filter)

@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
@active_required
def new_ticket():
    """Criar novo ticket"""
    form = TicketForm()
    
    if form.validate_on_submit():
        ticket = Ticket(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            priority=form.priority.data,
            user_id=current_user.id
        )
        db.session.add(ticket)
        db.session.commit()
        
        # Sem pontos para criar ticket (apenas resolver)
        flash('Ticket criado com sucesso!', 'success')
        return redirect(url_for('view_ticket', ticket_id=ticket.id))
    
    return render_template('tickets/new.html', form=form)

@app.route('/tickets/<int:ticket_id>')
@login_required
@active_required
def view_ticket(ticket_id):
    """Visualizar ticket - Apenas criador ou admin/técnico"""
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Verifica permissão
    if not current_user.can_view_ticket(ticket):
        flash('Você não tem permissão para ver este ticket.', 'danger')
        return redirect(url_for('tickets_list'))
    
    # Filtra comentários baseado no role
    if current_user.role in ['admin', 'technician']:
        comments = ticket.comments
    else:
        # Usuários normais não veem comentários internos
        comments = [c for c in ticket.comments if not c.is_internal]
    
    comment_form = CommentForm()
    return render_template('tickets/view.html', 
                         ticket=ticket, 
                         comments=comments,
                         comment_form=comment_form)

@app.route('/tickets/<int:ticket_id>/comment', methods=['POST'])
@login_required
@active_required
def add_comment(ticket_id):
    """Adicionar comentário ao ticket"""
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Verifica permissão
    if not current_user.can_view_ticket(ticket):
        flash('Você não tem permissão para comentar neste ticket.', 'danger')
        return redirect(url_for('tickets_list'))
    
    form = CommentForm()
    
    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            ticket_id=ticket_id,
            user_id=current_user.id,
            is_internal=form.is_internal.data if current_user.role in ['admin', 'technician'] else False
        )
        db.session.add(comment)
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Pontos apenas para técnicos/admin ao comentar
        if current_user.role in ['admin', 'technician']:
            current_user.add_points(5)  # Pontos por comentar
        flash('Comentário adicionado!', 'success')
    
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

# ==================== ROTAS DE RELATÓRIOS ====================


# ==================== ROTAS DE ATUALIZAÇÃO DE TICKETS ====================

@app.route('/tickets/<int:ticket_id>/assign', methods=['POST'])
@login_required
@active_required
def assign_ticket(ticket_id):
    """Assumir ticket - Técnicos e Admin"""
    if current_user.role not in ['admin', 'technician']:
        return jsonify({'error': 'Sem permissão'}), 403
    
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Atribui ao usuário atual
    ticket.assigned_to = current_user.id
    ticket.status = 'in_progress'
    ticket.updated_at = datetime.utcnow()
    
    # Adiciona comentário automático
    comment = Comment(
        content=f'Ticket assumido por {current_user.full_name}',
        ticket_id=ticket_id,
        user_id=current_user.id,
        is_internal=True
    )
    db.session.add(comment)
    
    # Adiciona pontos
    current_user.add_points(15)
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Ticket assumido com sucesso!'})

@app.route('/tickets/<int:ticket_id>/update_status', methods=['POST'])
@login_required
@active_required
def update_ticket_status(ticket_id):
    """Atualizar status do ticket via AJAX"""
    if current_user.role not in ['admin', 'technician']:
        return jsonify({'error': 'Sem permissão'}), 403
    
    ticket = Ticket.query.get_or_404(ticket_id)
    
    data = request.get_json()
    new_status = data.get('status')
    
    valid_statuses = ['open', 'in_progress', 'resolved', 'closed']
    if new_status not in valid_statuses:
        return jsonify({'error': 'Status inválido'}), 400
    
    old_status = ticket.status
    ticket.status = new_status
    ticket.updated_at = datetime.utcnow()
    
    # Se resolvido, marca data e calcula tempo
    if new_status == 'resolved' and old_status != 'resolved':
        ticket.resolved_at = datetime.utcnow()
        if ticket.created_at:
            delta = ticket.resolved_at - ticket.created_at
            ticket.resolution_time = int(delta.total_seconds() / 60)
            
        # Adiciona pontos para o técnico
        if ticket.assigned_to == current_user.id:
            points = 25
            if ticket.priority == 'critical':
                points = 50
            elif ticket.priority == 'high':
                points = 35
            current_user.add_points(points)
    
    # Adiciona comentário automático
    status_messages = {
        'in_progress': 'Status alterado para Em Andamento',
        'resolved': 'Ticket resolvido',
        'closed': 'Ticket fechado',
        'open': 'Ticket reaberto'
    }
    
    comment = Comment(
        content=f'{status_messages.get(new_status, "Status atualizado")} por {current_user.full_name}',
        ticket_id=ticket_id,
        user_id=current_user.id,
        is_internal=True
    )
    db.session.add(comment)
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Status atualizado para {new_status}!'})

# ==================== ROTAS DE RELATÓRIOS ====================

@app.route('/reports')
@login_required
@active_required
def reports():
    """Relatórios - Apenas admin/técnico"""
    if current_user.role not in ['admin', 'technician']:
        flash('Acesso negado', 'danger')
        return redirect(url_for('dashboard'))
    
    # Estatísticas gerais
    total_tickets = Ticket.query.count()
    
    # Tickets por status - Convertendo para lista de tuplas
    status_query = db.session.query(
        Ticket.status, 
        db.func.count(Ticket.id)
    ).group_by(Ticket.status).all()
    
    # Agrupa resolved e closed como resolvidos
    status_dict = {}
    for status, count in status_query:
        if status in ['resolved', 'closed']:
            status_dict['resolved'] = status_dict.get('resolved', 0) + count
        else:
            status_dict[status] = count
    
    tickets_by_status = [(str(k), int(v)) for k, v in status_dict.items()]
    
    # Tickets por prioridade - Convertendo para lista de tuplas
    priority_query = db.session.query(
        Ticket.priority,
        db.func.count(Ticket.id)
    ).group_by(Ticket.priority).all()
    tickets_by_priority = [(str(row[0]), int(row[1])) for row in priority_query] if priority_query else []
    
    # Tickets por categoria - Convertendo para lista de tuplas
    category_query = db.session.query(
        Ticket.category,
        db.func.count(Ticket.id)
    ).group_by(Ticket.category).all()
    tickets_by_category = [(str(row[0]), int(row[1])) for row in category_query] if category_query else []
    
    # Estatísticas de usuários (apenas admin)
    user_stats = None
    if current_user.role == 'admin':
        user_stats = {
            'total': User.query.count(),
            'active': User.query.filter_by(is_active=True).count(),
            'admins': User.query.filter_by(role='admin').count(),
            'technicians': User.query.filter_by(role='technician').count(),
            'users': User.query.filter_by(role='user').count()
        }
    
    return render_template('dashboard/reports.html',
                         total_tickets=total_tickets,
                         tickets_by_status=tickets_by_status,
                         tickets_by_priority=tickets_by_priority,
                         tickets_by_category=tickets_by_category,
                         user_stats=user_stats)

# ==================== TRATAMENTO DE ERROS ====================

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Página não encontrada'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', error='Acesso negado'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error='Erro interno do servidor'), 500

# ==================== COMANDOS CLI ====================

@app.cli.command()
def init_db():
    """Inicializa o banco de dados"""
    db.create_all()
    print("✓ Banco de dados inicializado!")

@app.cli.command()
def create_admin():
    """Cria um usuário administrador"""
    print("Criando usuário administrador...")
    
    username = input("Username: ") or "admin"
    email = input("Email: ") or "admin@helpdesk.com"
    full_name = input("Nome completo: ") or "Administrador"
    password = input("Senha: ") or "admin123"
    
    # Verifica se já existe
    if User.query.filter_by(username=username).first():
        print("❌ Usuário já existe!")
        return
    
    admin = User(
        username=username,
        email=email,
        full_name=full_name,
        department='TI',
        role='admin',
        points=1000,
        level=10
    )
    admin.set_password(password)
    
    db.session.add(admin)
    db.session.commit()
    
    print(f"✓ Admin criado: {username} / {password}")

@app.cli.command()
def seed_db():
    """Cria dados de exemplo"""
    # Verifica se já existem usuários
    if User.query.count() > 0:
        print("⚠️  Já existem usuários no banco!")
        if input("Deseja continuar? (s/n): ").lower() != 's':
            return
    
    # Admin
    admin = User(
        username='admin',
        email='admin@helpdesk.com',
        full_name='Administrador Sistema',
        department='TI',
        role='admin',
        points=1000,
        level=10
    )
    admin.set_password('admin123')
    
    # Técnico
    tech = User(
        username='tecnico',
        email='tecnico@helpdesk.com',
        full_name='João Técnico',
        department='TI',
        role='technician',
        points=500,
        level=5,
        created_by=1  # Criado pelo admin
    )
    tech.set_password('tech123')
    
    # Usuários normais
    user1 = User(
        username='maria',
        email='maria@empresa.com',
        full_name='Maria Silva',
        department='Vendas',
        role='user',
        created_by=1
    )
    user1.set_password('maria123')
    
    user2 = User(
        username='jose',
        email='jose@empresa.com',
        full_name='José Santos',
        department='Financeiro',
        role='user',
        created_by=1
    )
    user2.set_password('jose123')
    
    db.session.add_all([admin, tech, user1, user2])
    db.session.commit()
    
    print("✓ Usuários de exemplo criados!")
    print("\nCredenciais:")
    print("  ADMIN: admin / admin123 (pode criar e gerenciar usuários)")
    print("  TÉCNICO: tecnico / tech123 (pode ver todos os tickets)")
    print("  USUÁRIO: maria / maria123 (só vê seus próprios tickets)")
    print("  USUÁRIO: jose / jose123 (só vê seus próprios tickets)")

# ==================== EXECUÇÃO ====================

if __name__ == '__main__':
    print("🚀 Iniciando HelpDesk TI - Sistema de Gerenciamento de Usuários")
    print(f"📁 Banco de dados: {db_path}")
    
    with app.app_context():
        try:
            db.create_all()
            print("✓ Banco de dados pronto!")
            
            user_count = User.query.count()
            admin_count = User.query.filter_by(role='admin').count()
            
            if user_count == 0:
                print("\n⚠️  Nenhum usuário encontrado.")
                print("   Execute 'flask seed-db' para criar usuários de exemplo")
                print("   Ou 'flask create-admin' para criar apenas um admin")
            else:
                print(f"✓ {user_count} usuário(s) encontrado(s)")
                print(f"  {admin_count} administrador(es)")
                
                if admin_count == 0:
                    print("\n⚠️  Nenhum administrador encontrado!")
                    print("   Execute 'flask create-admin' para criar um")
                
        except Exception as e:
            print(f"❌ Erro: {e}")
    
    print("\n🌐 Servidor rodando em: http://localhost:5000")
    print("   Pressione CTRL+C para parar\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)