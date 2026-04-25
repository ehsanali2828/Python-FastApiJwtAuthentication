# Python FastAPI JWT Authentication 

In this project i have added auth APIs like login, register, verify, forgot-password, reset-password, update-password and some article list to create APIs. I am using an async PostgreSQL connection with SqlAlchemy ORM.

# Installation
- Run docker and if you dont have then install it first.
- Configure your postgresql
- Create .env file
```bash
cp .env.example .env
```
- Add Postgresql config to .env
- Run docker
```bash
docker-compose up -d --build
```
or
```bash
docker compose up -d --build

- Run app with start.sh. It will do migrate migrations then run app 
```bash
chmod 755 start.sh
sh start.sh
```