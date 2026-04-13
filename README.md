# KR_3

## Установка

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Подготовка БД

```bash
python init_db.py
```

## Запуск

```bash
uvicorn main:app --reload
```

## Проверка (curl)

```bash
# SQLite register
curl -X POST -H "Content-Type: application/json" -d "{\"username\":\"test_user\",\"password\":\"12345\"}" http://127.0.0.1:8000/register
```

```bash
# JWT/RBAC register
curl -X POST -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"qwerty123\",\"role\":\"user\"}" http://127.0.0.1:8000/auth/register
```

```bash
# Basic login
curl -u alice:qwerty123 http://127.0.0.1:8000/login
```

```bash
# JWT login
curl -X POST -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"qwerty123\"}" http://127.0.0.1:8000/login
```
