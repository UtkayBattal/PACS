"""add leave requests table

Revision ID: a1b2c3d4e5f6
Revises: 542ea49e946b
Create Date: 2025-01-20 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '542ea49e946b'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # İzin talepleri tablosunu oluştur
    op.create_table('leave_requests',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('start_date', sa.DateTime(), nullable=False),
        sa.Column('end_date', sa.DateTime(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='bekleniyor'),
        sa.Column('request_date', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('approved_by', sa.Integer(), nullable=True),
        sa.Column('approved_date', sa.DateTime(), nullable=True),
        sa.Column('admin_notes', sa.Text(), nullable=True),
        sa.Column('leave_type', sa.String(length=50), nullable=True, server_default='Yıllık İzin'),
        sa.Column('days_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.text('now()')),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.ForeignKeyConstraint(['approved_by'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # İndeksler ekle
    op.create_index('ix_leave_requests_user_id', 'leave_requests', ['user_id'])
    op.create_index('ix_leave_requests_status', 'leave_requests', ['status'])
    op.create_index('ix_leave_requests_start_date', 'leave_requests', ['start_date'])


def downgrade() -> None:
    # İndeksleri kaldır
    op.drop_index('ix_leave_requests_start_date', table_name='leave_requests')
    op.drop_index('ix_leave_requests_status', table_name='leave_requests')
    op.drop_index('ix_leave_requests_user_id', table_name='leave_requests')
    
    # Tabloyu kaldır
    op.drop_table('leave_requests') 