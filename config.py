from pydantic import BaseSettings


class Settings(BaseSettings):
    app_name: str = "AnonimalAPI"

    class Config:
        env_file = ".env"
