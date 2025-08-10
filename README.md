# HelpDesk TI - Sistema de Suporte com Gamificação

## 🎮 Características

- **Sistema de Tickets**: Criação, acompanhamento e resolução de tickets
- **Gamificação Completa**: Pontos, níveis, badges e rankings
- **Dashboard Interativo**: Visualização em tempo real de métricas
- **Relatórios Detalhados**: Análises e gráficos de performance
- **Interface Moderna**: Design responsivo e intuitivo
- **Sistema de Notificações**: Alertas em tempo real
- **Gestão de Usuários**: Diferentes níveis de acesso

## 🚀 Instalação

1. Execute o script gerador:
```bash
python gerar_helpdesk.py
```

2. Entre no diretório do projeto:
```bash
cd helpdesk_ti
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Inicialize o banco de dados:
```bash
python app.py
```

5. (Opcional) Popule com dados de exemplo:
```bash
flask seed-db
```

## 👤 Usuários Padrão

- **Admin**: admin / admin123
- **Técnico**: tecnico / tech123
- **Usuário**: usuario / user123

## 🎯 Sistema de Gamificação

### Pontos
- Login diário: 5 pts
- Criar ticket: 10 pts
- Adicionar comentário: 5 pts
- Assumir ticket: 15 pts
- Resolver ticket: 25-50 pts (baseado na prioridade)
- Avaliação 5 estrelas: 10 pts bonus

### Badges
- Primeiro Ticket
- 10/50 Tickets Criados
- Primeiro Resolvido
- 25/100 Resoluções
- Semana Produtiva (7 dias consecutivos)
- Mês Dedicado (30 dias consecutivos)
- Excelência (10 avaliações 5 estrelas)

### Níveis
- A cada 100 pontos = 1 nível
- Badges especiais por nível

## 📊 Recursos

### Dashboard
- Estatísticas em tempo real
- Gráficos interativos
- Ranking de usuários
- Tickets recentes
- Métricas de performance

### Tickets
- Categorias: Hardware, Software, Rede, Impressora, Email, Acesso, Outros
- Prioridades: Baixa, Média, Alta, Crítica
- Status: Aberto, Em Andamento, Resolvido, Fechado
- Sistema de comentários
- Avaliação de satisfação

### Relatórios
- Tickets por status/categoria/prioridade
- Conformidade SLA
- Tempo médio de resolução
- Top técnicos
- Evolução temporal

## 🛠️ Tecnologias

- **Backend**: Flask, SQLAlchemy
- **Frontend**: Bootstrap 5, Chart.js
- **Banco de Dados**: SQLite
- **Autenticação**: Flask-Login
- **Formulários**: Flask-WTF

## 📱 Interface Responsiva

O sistema é totalmente responsivo e funciona em:
- Desktop
- Tablet
- Smartphone

## 🔒 Segurança

- Senhas criptografadas
- CSRF Protection
- Controle de acesso por roles
- Validação de formulários

## 📈 Métricas e KPIs

- Total de tickets
- Taxa de resolução
- Tempo médio de atendimento
- Satisfação do cliente
- Conformidade SLA
- Produtividade por técnico

## 🎨 Personalização

O sistema pode ser facilmente personalizado:
- Cores e temas
- Categorias de tickets
- Níveis de prioridade
- Regras de gamificação
- Relatórios customizados

## 📝 Licença

MIT License - Sinta-se livre para usar e modificar!