import os


class Config:
    """
    a class for setting access token environment variable and provider`s path.
    can be changed according to needs
    """
    PROVIDER = "GITHUB"
    ACCESS_TOKEN = os.environ.get('GITHUB_ACCESS_TOKEN')

