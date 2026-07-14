"""SQLAlchemy ORM models for local identity state tracking."""

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class LocalUser(Base):
    """Tracks identity state synced from Entra ID via SCIM."""

    __tablename__ = "local_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entra_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    given_name: Mapped[str] = mapped_column(String, nullable=False)
    family_name: Mapped[str] = mapped_column(String, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
