# PACS - Personnel Attendance Control System

## 📋 About the Project

PACS (Personnel Attendance Control System) is a Docker-based personnel attendance control and leave tracking system that works integrated with ZKTeco fingerprint terminals. The system is developed using modern web technologies and designed with microservice architecture.

## 🏗️ System Architecture

The project consists of 3 main components:

### 1. **DataBase** - Database Service
- **Technology**: PostgreSQL 14 + Python 3.9
- **Purpose**: Central database management
- **Features**:
  - Data modeling with SQLAlchemy ORM
  - Database migration management with Alembic
  - Automatic table creation and default data insertion

### 2. **PDKS_Listener** - Terminal Listener Service
- **Technology**: Python 3.9 + pyzk library
- **Purpose**: Data collection from ZKTeco terminals
- **Features**:
  - Real-time terminal connection
  - Automatic attendance data synchronization
  - Automatic user information transfer
  - Automatic reconnection in case of connection loss
  - Advanced error handling and logging

### 3. **PDKS_Panel** - Web Management Panel
- **Technology**: Flask + SQLAlchemy + Bootstrap
- **Purpose**: Web-based management interface
- **Features**:
  - User management and authentication
  - Terminal management and configuration
  - Detailed reporting system (PDF/Excel export)
  - Leave request management
  - Real-time dashboard

## 🚀 Installation and Running

### Requirements
- Docker and Docker Compose
- At least 4GB RAM
- Network access (for terminals)

### Quick Start

1. **Clone the project:**
```bash
git clone <repository-url>
cd PACS
```

2. **Start the database service:**
```bash
cd DataBase
docker-compose up -d
```

3. **Start the web panel:**
```bash
cd ../PDKS_Panel
docker-compose up -d
```

4. **Start the terminal listener:**
```bash
cd ../PDKS_Listener
# Edit the .env file (add terminal IP addresses)
docker-compose up -d
```

### Detailed Installation

#### 1. Database Installation

```bash
cd DataBase
# Start PostgreSQL with Docker Compose
docker-compose up -d

# Check database status
docker logs pdks_database
```

**Default Database Information:**
- Host: localhost:5433
- Database: myapp_db
- Username: dbuser
- Password: dbpass123

#### 2. Web Panel Installation

```bash
cd PDKS_Panel
# Create environment file
cp WebService/panel/.env.example WebService/panel/.env

# Start with Docker
docker-compose up -d
```

**Default Panel Access:**
- URL: http://localhost:5000
- Admin Email: admin@admin.com
- Admin Password: admin

#### 3. Terminal Listener Installation

```bash
cd PDKS_Listener
# Create environment file
cp .env.example .env

# Add terminal IP addresses to .env file
echo "DEVICE_IP=192.168.1.100" >> .env
echo "DEVICE_PORT=4370" >> .env

# Start with Docker
docker-compose up -d
```

## 📊 Database Schema

### Main Tables

#### Users (Users)
- `user_id`: Primary key
- `name`: Full name
- `email`: Email address
- `password`: Encrypted password
- `role_id`: Role reference
- `department_id`: Department reference
- `card_no`: Card number
- `device_role`: Terminal privilege level
- `status`: Active/Inactive status

#### Devices (Terminals)
- `device_id`: Primary key
- `name`: Terminal name
- `ip`: IP address
- `port`: Port number
- `location_id`: Location reference
- `is_active`: Active status
- `last_connection`: Last connection time

#### Records (Records)
- `id`: Primary key
- `user_id`: User reference
- `device_id`: Terminal reference
- `timestamp`: Record time
- `punch`: Entry/Exit (0/1)
- `status`: Status information

#### LeaveRequests (Leave Requests)
- `id`: Primary key
- `user_id`: Requesting user
- `start_date`: Leave start date
- `end_date`: Leave end date
- `reason`: Leave reason
- `status`: Request status (pending/approved/rejected)
- `approved_by`: Approving admin

## 🔧 Configuration

### Environment Variables

#### DataBase (.env)
```env
POSTGRES_USER=dbuser
POSTGRES_PASSWORD=dbpass123
POSTGRES_DB=myapp_db
POSTGRES_PORT=5433
```

#### PDKS_Panel (.env)
```env
DB_USER=dbuser
DB_PASSWORD=dbpass123
DB_HOST=pdks_database
DB_PORT=5433
DB_NAME=myapp_db
FLASK_ENV=production
SECRET_KEY=your-secret-key
```

#### PDKS_Listener (.env)
```env
DEVICE_IP=192.168.1.100
DEVICE_PORT=4370
DEVICE_TIMEOUT=5
DB_HOST=pdks_database
DB_USER=dbuser
DB_PASSWORD=dbpass123
DB_NAME=myapp_db
DB_PORT=5433
CHECK_INTERVAL=30
RECONNECT_INTERVAL=300
CLEAR_ATTENDANCE=true
```

## 📈 Features

### 🎯 Core Features
- **Real-time Data Collection**: Instant synchronization of terminal data
- **Multi-terminal Support**: Managing multiple terminals simultaneously
- **Automatic User Synchronization**: Automatic transfer of terminal users
- **Advanced Error Handling**: Automatic reconnection in case of connection loss

### 📊 Reporting System
- **Personnel List**: Detailed information of all personnel
- **Detailed Entry-Exit**: Time-based detailed records
- **Timesheet Reports**: Daily, weekly and period-based timesheets
- **Excel/PDF Export**: Download reports in different formats
- **Filtering**: Department, date, user-based filtering

### 👥 User Management
- **Role-based Authorization**: Admin, Supervisor, User roles
- **Secure Authentication**: Password hashing with PBKDF2
- **Profile Management**: Update user information
- **Department Management**: Department-based organization

### 📅 Leave Management
- **Leave Requests**: Personnel leave request creation
- **Approval Process**: Leave management with admin approval
- **Leave Tracking**: Used and remaining leave days
- **Automatic Calculation**: Automatic calculation of leave days

### 🔧 Terminal Management
- **Terminal Configuration**: IP, port and setting management
- **Connection Status**: Real-time terminal status
- **User Transfer**: Transfer terminal users to system
- **Fingerprint Management**: Fingerprint registration and deletion operations

## 🛠️ API Endpoints

### Authentication
- `POST /login` - User login
- `POST /logout` - User logout
- `GET /profile` - User profile

### Terminal Management
- `GET /devices` - Terminal list
- `POST /devices` - Add new terminal
- `PUT /devices/<id>` - Update terminal
- `DELETE /devices/<id>` - Delete terminal

### Reporting
- `POST /reports/generate` - Generate report
- `POST /reports/download` - Download report
- `GET /reports/api/active-users-count` - Active user count

### Leave Management
- `GET /leave-requests/employee` - Employee leave panel
- `POST /leave-requests/employee/create` - Create leave request
- `GET /leave-requests/admin` - Admin leave panel
- `POST /leave-requests/admin/approve/<id>` - Approve leave
- `POST /leave-requests/admin/reject/<id>` - Reject leave

## 🔒 Security

### Authentication
- Password hashing with PBKDF2
- Session-based authentication
- Role-based access control

### Data Security
- SQL Injection protection (SQLAlchemy ORM)
- XSS protection (Flask-WTF)
- CSRF protection
- Secure database connections

### Network Security
- Docker network isolation
- Port management
- Sensitive information protection with environment variables

## 📝 Logging

### Log Levels
- **INFO**: General information messages
- **WARNING**: Warning messages
- **ERROR**: Error messages
- **CRITICAL**: Critical error messages
- **SUCCESS**: Successful operation messages

### Log Files
- `pdks_listener.log`: Terminal listener logs
- `pdks_web.log`: Web panel logs
- `pdks_database.log`: Database logs

## 🐛 Troubleshooting

### Common Issues

#### Terminal Connection Issues
```bash
# Check terminal IP
ping 192.168.1.100

# Check port accessibility
telnet 192.168.1.100 4370

# Check Docker logs
docker logs pdks-listener
```

#### Database Connection Issues
```bash
# Check database container status
docker ps | grep pdks_database

# Check database logs
docker logs pdks_database

# Test connection
docker exec -it pdks_database psql -U dbuser -d myapp_db
```

#### Web Panel Access Issues
```bash
# Check container status
docker ps | grep pdks-web

# Check port accessibility
curl http://localhost:5000

# Check logs
docker logs pdks-web
```

### Performance Optimization

#### Database Optimization
- Ensure indexes are properly defined
- Use pagination for large datasets
- Optimize unnecessary queries

#### Terminal Connection Optimization
- Adjust `CHECK_INTERVAL` value
- Optimize `RECONNECT_INTERVAL` value
- Set `batch_size` for batch operations

## 🔄 Updates and Maintenance

### Database Migration
```bash
cd DataBase
# Create new migration
alembic revision --autogenerate -m "migration_description"

# Apply migration
alembic upgrade head
```

### Container Updates
```bash
# Update all services
docker-compose pull
docker-compose up -d

# Clean old images
docker image prune -f
```

### Backup
```bash
# Database backup
docker exec pdks_database pg_dump -U dbuser myapp_db > backup.sql

# Container backup
docker save pdks_database > pdks_database.tar
```

## 📞 Support and Contributing

### Developer Information
- **Project**: PACS - Personnel Attendance Control System
- **Technology**: Python, Flask, PostgreSQL, Docker
- **Architecture**: Microservice

### Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### License
This project is licensed under the MIT License.

## 📚 Additional Resources

### Documentation
- [Flask Documentation](https://flask.palletsprojects.com/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Docker Documentation](https://docs.docker.com/)
- [ZKTeco Terminal Documentation](https://www.zkteco.com/)

### Useful Commands
```bash
# Start all services
docker-compose -f DataBase/docker-compose.yml up -d
docker-compose -f PDKS_Panel/docker-compose.yml up -d
docker-compose -f PDKS_Listener/docker-compose.yml up -d

# Stop services
docker-compose -f DataBase/docker-compose.yml down
docker-compose -f PDKS_Panel/docker-compose.yml down
docker-compose -f PDKS_Listener/docker-compose.yml down

# Follow logs
docker logs -f pdks-listener
docker logs -f pdks-web
docker logs -f pdks_database
```

---

**Note**: This system has been tested with ZKTeco fingerprint terminals. Additional configuration may be required for different terminal brands.
