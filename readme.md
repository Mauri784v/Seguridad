## Instalar dependencias

ver requirements.txt

## Pasos para ejecutar
## 1.- Crear entorno virtual
python -m venv "nombre del entorno"
## 2.- Activar el entorno virtual (venv)
.\"nombre del entorno"/Scripts/activate
## 3.- Instalar dependencias
pip install -r requirements
## 4.- python "nombre del archivo"
ejemplo: python app_vulnerable.py


## R E G I S T R O

curl -X POST http://127.0.0.1:5000/register ^
-H "Content-Type: application/json" ^
-d "{\"username\": \"FOALS\", \"password\": \"mountains\", \"email\": \"admin@localhost\", \"birthdate\": \"2003-07-10\", \"secret_question\": \"¿Cual es tu mascota?\", \"secret_answer\": \"tiburon\"}"


## L O G I N 
curl -X POST http://127.0.0.1:5000/login -d "username=admin" -d "password=1234"


## CREAR PERMISO

Token foals pruebas: 55c4eea5-f730-42bb-a36b-de2a0ca6f7a6

curl -X POST http://127.0.0.1:5000/permissions ^
-H "Content-Type: application/json" ^
-H "Authorization: 0da1cb27-989a-410a-8555-17cdf98214aa" ^
-d "{\"name\": \"crear_usuario\"}"

## LISTAR PERMISOS

curl -X GET http://127.0.0.1:5000/permissions ^
-H "Authorization: 7bc1d461-eb9f-4344-b3ee-d7fe2c500295"

## EDITAR UN PERMISO
curl -X PUT http://127.0.0.1:5000/permissions/1 ^
-H "Content-Type: application/json" ^
-H "Authorization: 55c4eea5-f730-42bb-a36b-de2a0ca6f7a6" ^
-d "{\"name\": \"FOALS\"}"

## ELIMINAR UN PERMISO
curl -X DELETE http://127.0.0.1:5000/permissions/1 ^
-H "Authorization: 0da1cb27-989a-410a-8555-17cdf98214aa"

## CREAR UN ROL
curl -X POST http://127.0.0.1:5000/roles ^
-H "Content-Type: application/json" ^
-H "Authorization: 0da1cb27-989a-410a-8555-17cdf98214aa" ^
-d "{\"name\": \"admin\"}"

## LISTAR ROLES
curl -X GET http://127.0.0.1:5000/roles ^
-H "Authorization: 0da1cb27-989a-410a-8555-17cdf98214aa"

## EDITAR UN ROL
curl -X PUT http://127.0.0.1:5000/roles/1 ^
-H "Content-Type: application/json" ^
-H "Authorization: 79e2e237-8158-4f18-be30-28637355e73a" ^
-d "{\"name\": \"superadmin\"}"

## ELIMINAR UN ROL
curl -X DELETE http://127.0.0.1:5000/roles/1 ^
-H "Authorization: 0da1cb27-989a-410a-8555-17cdf98214aa"

## VER TODOS LOS USUARIOS
curl -X GET http://127.0.0.1:5000/getData^
-H "Authorization: 0da1cb27-989a-410a-8555-17cdf98214aa"


curl -X GET http://127.0.0.1:5000/getUser ^
"Authorization: 7bc1d461-eb9f-4344-b3ee-d7fe2c500295"
