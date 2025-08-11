#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sistema de Helpdesk TI com Gamificação"""

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy import func, extract, and_, or_
import os
import secrets
import json
from pathlib import Path

# Configuração da aplicação
app = Flask(__name__)
# Criar diretório instance se não existir
instance_path = Path(__file__).parent / 'instance'
instance_path.mkdir(exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{instance_path}/helpdesk.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/helpdesk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

# Inicialização das extensões
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'

# ==================== MODELOS ====================

class User(UserMixin, db.Model):
    """Modelo de Usuário com sistema de gamificação"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')  # user, technician, admin
    department = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Gamificação
    points = db.Column(db.Integer, default=0)
    level = db.Column(db.Integer, default=1)
    badges = db.Column(db.Text, default='[]')  # JSON array
    streak_days = db.Column(db.Integer, default=0)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    tickets_created = db.relationship('Ticket', foreign_keys='Ticket.user_id', backref='creator', lazy='dynamic')
    tickets_assigned = db.relationship('Ticket', foreign_keys='Ticket.assigned_to', backref='technician', lazy='dynamic')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def add_points(self, points, reason=""):
        """Adiciona pontos e verifica level up"""
        self.points += points
        new_level = (self.points // 100) + 1
        if new_level > self.level:
            self.level = new_level
            self.add_badge(f"Nível {self.level}", f"level_{self.level}")
        db.session.commit()
    
    def add_badge(self, name, badge_id):
        """Adiciona uma badge ao usuário"""
        badges = json.loads(self.badges) if self.badges else []
        if badge_id not in [b.get('id') for b in badges]:
            badges.append({'id': badge_id, 'name': name, 'date': datetime.utcnow().isoformat()})
            self.badges = json.dumps(badges)
            db.session.commit()
    
    def get_badges(self):
        """Retorna lista de badges"""
        return json.loads(self.badges) if self.badges else []
    
    def update_streak(self):
        """Atualiza streak de dias consecutivos"""
        now = datetime.utcnow()
        if self.last_activity:
            days_diff = (now.date() - self.last_activity.date()).days
            if days_diff == 1:
                self.streak_days += 1
                if self.streak_days == 7:
                    self.add_badge("Semana Produtiva", "streak_7")
                elif self.streak_days == 30:
                    self.add_badge("Mês Dedicado", "streak_30")
            elif days_diff > 1:
                self.streak_days = 1
        else:
            self.streak_days = 1
        self.last_activity = now
        db.session.commit()

class Ticket(db.Model):
    """Modelo de Ticket"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='open')
    
    # Relacionamentos
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    # Métricas
    resolution_time = db.Column(db.Integer)  # em minutos
    satisfaction_rating = db.Column(db.Integer)  # 1-5
    
    # Relacionamentos
    comments = db.relationship('Comment', backref='ticket', lazy='dynamic', cascade='all, delete-orphan')
    
    def calculate_resolution_time(self):
        """Calcula tempo de resolução em minutos"""
        if self.resolved_at and self.created_at:
            delta = self.resolved_at - self.created_at
            self.resolution_time = int(delta.total_seconds() / 60)
            return self.resolution_time
        return None

class Comment(db.Model):
    """Modelo de Comentário"""
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_internal = db.Column(db.Boolean, default=False)

# ==================== FORMULÁRIOS ====================

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    full_name = StringField('Nome Completo', validators=[DataRequired()])
    department = StringField('Departamento', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])

class TicketForm(FlaskForm):
    title = StringField('Título', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Descrição', validators=[DataRequired()])
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
    is_internal = SelectField('Tipo', choices=[('0', 'Público'), ('1', 'Interno')], default='0')

class RatingForm(FlaskForm):
    rating = IntegerField('Avaliação', validators=[DataRequired()])

# ==================== LOGIN MANAGER ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== ROTAS DE AUTENTICAÇÃO ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=True)
            user.update_streak()
            user.add_points(5, "Login diário")
            flash('Login realizado com sucesso!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        flash('Usuário ou senha incorretos', 'danger')
    return render_template('auth/login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            full_name=form.full_name.data,
            department=form.department.data
        )
        user.set_password(form.password.data)
        user.add_badge("Bem-vindo!", "welcome")
        db.session.add(user)
        db.session.commit()
        flash('Registro realizado com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso!', 'info')
    return redirect(url_for('login'))

# ==================== ROTAS PRINCIPAIS ====================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Estatísticas gerais
    total_tickets = Ticket.query.count()
    open_tickets = Ticket.query.filter_by(status='open').count()
    in_progress = Ticket.query.filter_by(status='in_progress').count()
    resolved = Ticket.query.filter_by(status='resolved').count()
    
    # Tickets do usuário
    if current_user.role in ['technician', 'admin']:
        my_tickets = Ticket.query.filter_by(assigned_to=current_user.id).limit(5).all()
        recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(10).all()
    else:
        my_tickets = current_user.tickets_created.order_by(Ticket.created_at.desc()).limit(5).all()
        recent_tickets = my_tickets
    
    # Top usuários (gamificação)
    top_users = User.query.order_by(User.points.desc()).limit(5).all()
    
    # Métricas de tempo
    avg_resolution = db.session.query(func.avg(Ticket.resolution_time)).filter(
        Ticket.resolution_time.isnot(None)
    ).scalar() or 0
    
    stats = {
        'total': total_tickets,
        'open': open_tickets,
        'in_progress': in_progress,
        'resolved': resolved,
        'avg_resolution': round(avg_resolution / 60, 1) if avg_resolution else 0  # em horas
    }
    
    return render_template('dashboard/index.html', 
                         stats=stats, 
                         my_tickets=my_tickets,
                         recent_tickets=recent_tickets,
                         top_users=top_users)

# ==================== ROTAS DE TICKETS ====================

@app.route('/tickets')
@login_required
def tickets_list():
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    
    query = Ticket.query
    
    if current_user.role not in ['technician', 'admin']:
        query = query.filter_by(user_id=current_user.id)
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    tickets = query.order_by(Ticket.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    return render_template('tickets/list.html', tickets=tickets, status_filter=status_filter)

@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
def new_ticket():
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
        
        # Gamificação
        current_user.add_points(10, "Ticket criado")
        
        # Verificar conquistas
        ticket_count = current_user.tickets_created.count()
        if ticket_count == 1:
            current_user.add_badge("Primeiro Ticket", "first_ticket")
        elif ticket_count == 10:
            current_user.add_badge("10 Tickets", "tickets_10")
        elif ticket_count == 50:
            current_user.add_badge("50 Tickets", "tickets_50")
        
        flash('Ticket criado com sucesso!', 'success')
        return redirect(url_for('view_ticket', ticket_id=ticket.id))
    
    return render_template('tickets/new.html', form=form)

@app.route('/tickets/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Verificar permissão
    if current_user.role not in ['technician', 'admin'] and ticket.user_id != current_user.id:
        flash('Você não tem permissão para ver este ticket.', 'danger')
        return redirect(url_for('tickets_list'))
    
    comments = ticket.comments.order_by(Comment.created_at.asc()).all()
    comment_form = CommentForm()
    
    return render_template('tickets/view.html', 
                         ticket=ticket, 
                         comments=comments,
                         comment_form=comment_form)

@app.route('/tickets/<int:ticket_id>/comment', methods=['POST'])
@login_required
def add_comment(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    form = CommentForm()
    
    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            ticket_id=ticket_id,
            user_id=current_user.id,
            is_internal=bool(int(form.is_internal.data))
        )
        db.session.add(comment)
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        
        current_user.add_points(5, "Comentário adicionado")
        flash('Comentário adicionado com sucesso!', 'success')
    
    return redirect(url_for('view_ticket', ticket_id=ticket_id))

@app.route('/tickets/<int:ticket_id>/assign', methods=['POST'])
@login_required
def assign_ticket(ticket_id):
    if current_user.role not in ['technician', 'admin']:
        return jsonify({'error': 'Sem permissão'}), 403
    
    ticket = Ticket.query.get_or_404(ticket_id)
    technician_id = request.json.get('technician_id')
    
    if technician_id == 'self':
        ticket.assigned_to = current_user.id
        ticket.status = 'in_progress'
        current_user.add_points(15, "Ticket assumido")
    else:
        technician = User.query.get(technician_id)
        if technician and technician.role in ['technician', 'admin']:
            ticket.assigned_to = technician.id
            ticket.status = 'in_progress'
    
    ticket.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/tickets/<int:ticket_id>/update_status', methods=['POST'])
@login_required
def update_ticket_status(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    
    if current_user.role not in ['technician', 'admin'] and ticket.user_id != current_user.id:
        return jsonify({'error': 'Sem permissão'}), 403
    
    new_status = request.json.get('status')
    if new_status in ['open', 'in_progress', 'resolved', 'closed']:
        old_status = ticket.status
        ticket.status = new_status
        ticket.updated_at = datetime.utcnow()
        
        if new_status == 'resolved' and old_status != 'resolved':
            ticket.resolved_at = datetime.utcnow()
            ticket.calculate_resolution_time()
            
            if ticket.assigned_to:
                technician = User.query.get(ticket.assigned_to)
                if technician:
                    points = 25
                    if ticket.priority == 'critical':
                        points = 50
                    elif ticket.priority == 'high':
                        points = 35
                    technician.add_points(points, f"Ticket {ticket.priority} resolvido")
                    
                    # Conquistas de resolução
                    resolved_count = Ticket.query.filter_by(
                        assigned_to=technician.id,
                        status='resolved'
                    ).count()
                    
                    if resolved_count == 1:
                        technician.add_badge("Primeiro Resolvido", "first_resolved")
                    elif resolved_count == 25:
                        technician.add_badge("25 Resoluções", "resolved_25")
                    elif resolved_count == 100:
                        technician.add_badge("100 Resoluções", "resolved_100")
        
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Status inválido'}), 400

@app.route('/tickets/<int:ticket_id>/rate', methods=['POST'])
@login_required
def rate_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    
    if ticket.user_id != current_user.id:
        return jsonify({'error': 'Sem permissão'}), 403
    
    rating = request.json.get('rating')
    if rating and 1 <= rating <= 5:
        ticket.satisfaction_rating = rating
        db.session.commit()
        
        # Bonus para técnico bem avaliado
        if ticket.assigned_to and rating >= 4:
            technician = User.query.get(ticket.assigned_to)
            if technician:
                bonus = 10 if rating == 5 else 5
                technician.add_points(bonus, f"Avaliação {rating} estrelas")
                
                # Badge de excelência
                excellent_ratings = Ticket.query.filter_by(
                    assigned_to=technician.id,
                    satisfaction_rating=5
                ).count()
                if excellent_ratings == 10:
                    technician.add_badge("Excelência", "excellence")
        
        return jsonify({'success': True})
    
    return jsonify({'error': 'Avaliação inválida'}), 400

# ==================== ROTAS DE RELATÓRIOS ====================

@app.route('/reports')
@login_required
def reports():
    if current_user.role not in ['technician', 'admin']:
        flash('Acesso negado', 'danger')
        return redirect(url_for('dashboard'))
    
    # Período do relatório (últimos 30 dias por padrão)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    
    # Tickets por status
    status_data = db.session.query(
        Ticket.status, 
        func.count(Ticket.id)
    ).filter(
        Ticket.created_at.between(start_date, end_date)
    ).group_by(Ticket.status).all()
    
    # Tickets por categoria
    category_data = db.session.query(
        Ticket.category,
        func.count(Ticket.id)
    ).filter(
        Ticket.created_at.between(start_date, end_date)
    ).group_by(Ticket.category).all()
    
    # Tickets por prioridade
    priority_data = db.session.query(
        Ticket.priority,
        func.count(Ticket.id)
    ).filter(
        Ticket.created_at.between(start_date, end_date)
    ).group_by(Ticket.priority).all()
    
    # Evolução diária
    daily_tickets = db.session.query(
        func.date(Ticket.created_at).label('date'),
        func.count(Ticket.id).label('count')
    ).filter(
        Ticket.created_at.between(start_date, end_date)
    ).group_by(func.date(Ticket.created_at)).all()
    
    # Top técnicos
    top_technicians = db.session.query(
        User.full_name,
        func.count(Ticket.id).label('resolved_count'),
        func.avg(Ticket.satisfaction_rating).label('avg_rating')
    ).join(
        Ticket, Ticket.assigned_to == User.id
    ).filter(
        Ticket.status == 'resolved',
        Ticket.resolved_at.between(start_date, end_date)
    ).group_by(User.id).order_by(func.count(Ticket.id).desc()).limit(5).all()
    
    # Tempo médio de resolução por prioridade
    resolution_times = db.session.query(
        Ticket.priority,
        func.avg(Ticket.resolution_time).label('avg_time')
    ).filter(
        Ticket.resolved_at.between(start_date, end_date),
        Ticket.resolution_time.isnot(None)
    ).group_by(Ticket.priority).all()
    
    # SLA (considerando tempos em minutos)
    sla_targets = {'critical': 240, 'high': 480, 'medium': 1440, 'low': 2880}
    sla_compliance = {}
    for priority, target in sla_targets.items():
        total = Ticket.query.filter(
            Ticket.priority == priority,
            Ticket.resolved_at.between(start_date, end_date)
        ).count()
        
        within_sla = Ticket.query.filter(
            Ticket.priority == priority,
            Ticket.resolved_at.between(start_date, end_date),
            Ticket.resolution_time <= target
        ).count()
        
        if total > 0:
            sla_compliance[priority] = round((within_sla / total) * 100, 1)
        else:
            sla_compliance[priority] = 100
    
    return render_template('dashboard/reports.html',
                         status_data=status_data,
                         category_data=category_data,
                         priority_data=priority_data,
                         daily_tickets=daily_tickets,
                         top_technicians=top_technicians,
                         resolution_times=resolution_times,
                         sla_compliance=sla_compliance)

# ==================== ROTAS DE ADMIN ====================

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Acesso negado', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>/update_role', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Sem permissão'}), 403
    
    user = User.query.get_or_404(user_id)
    new_role = request.json.get('role')
    
    if new_role in ['user', 'technician', 'admin']:
        user.role = new_role
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Role inválida'}), 400

# ==================== API ENDPOINTS ====================

@app.route('/api/stats')
@login_required
def api_stats():
    """API para estatísticas em tempo real"""
    stats = {
        'tickets': {
            'total': Ticket.query.count(),
            'open': Ticket.query.filter_by(status='open').count(),
            'in_progress': Ticket.query.filter_by(status='in_progress').count(),
            'resolved': Ticket.query.filter_by(status='resolved').count()
        },
        'user': {
            'points': current_user.points,
            'level': current_user.level,
            'streak': current_user.streak_days,
            'badges_count': len(current_user.get_badges())
        }
    }
    return jsonify(stats)

@app.route('/api/leaderboard')
@login_required
def api_leaderboard():
    """API para ranking de usuários"""
    users = User.query.order_by(User.points.desc()).limit(10).all()
    leaderboard = [{
        'rank': i + 1,
        'name': user.full_name,
        'points': user.points,
        'level': user.level,
        'badges': len(user.get_badges())
    } for i, user in enumerate(users)]
    return jsonify(leaderboard)

# ==================== CONTEXTO DE TEMPLATE ====================

@app.context_processor
def inject_globals():
    """Injeta variáveis globais nos templates"""
    return {
        'priority_colors': {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'dark'
        },
        'status_colors': {
            'open': 'info',
            'in_progress': 'warning',
            'resolved': 'success',
            'closed': 'secondary'
        },
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

# ==================== COMANDOS CLI ====================

@app.cli.command()
def init_db():
    """Inicializa o banco de dados"""
    db.create_all()
    print("Banco de dados inicializado!")

@app.cli.command()
def seed_db():
    """Popula o banco com dados de exemplo"""
    # Criar usuário admin
    admin = User(
        username='admin',
        email='admin@helpdesk.com',
        full_name='Administrador',
        department='TI',
        role='admin'
    )
    admin.set_password('admin123')
    admin.points = 1000
    admin.level = 10
    db.session.add(admin)
    
    # Criar técnico
    tech = User(
        username='tecnico',
        email='tecnico@helpdesk.com',
        full_name='João Técnico',
        department='TI',
        role='technician'
    )
    tech.set_password('tech123')
    tech.points = 500
    tech.level = 5
    db.session.add(tech)
    
    # Criar usuário comum
    user = User(
        username='usuario',
        email='usuario@empresa.com',
        full_name='Maria Silva',
        department='Vendas',
        role='user'
    )
    user.set_password('user123')
    db.session.add(user)
    
    db.session.commit()
    print("Dados de exemplo criados!")
    print("Usuários criados:")
    print("  Admin: admin / admin123")
    print("  Técnico: tecnico / tech123")
    print("  Usuário: usuario / user123")

# ==================== EXECUÇÃO ====================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
