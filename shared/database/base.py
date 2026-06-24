from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    metadata: type  # satisfy type checker

