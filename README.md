Я знаю пока что только, как использовать SQLite3, не бейте пожалуйста. Для тестирования можно использовать Postman.
1. Получаем токены с помощью GET запроса и указания user_id.
<img width="1440" alt="Снимок экрана 2024-12-08 в 21 27 27" src="https://github.com/user-attachments/assets/152c6151-0b34-4b4c-ad92-c6611554e1ff">
2. Обновляем токены с помощью POST запроса, используя refresh токен из тела предыдущего запроса и того же самого user_id.
<img width="1440" alt="Снимок экрана 2024-12-08 в 21 27 48" src="https://github.com/user-attachments/assets/c77d2566-1184-4bbd-89cc-c69379df973d">

Также сделала два теста в main_test.go на проверку занесения в базу пользователя с указанием и без указания user_id. Для проверки запустить go test
Не все реализовала, в частности отправку сообщеения на email.  Так что мне есть куда стремиться! :) 
Само задание: 
**Используемые технологии:**

- Go
- JWT
- PostgreSQL

**Задание:**

Написать часть сервиса аутентификации.

Два REST маршрута:

- Первый маршрут выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса
- Второй маршрут выполняет Refresh операцию на пару Access, Refresh токенов

**Требования:**

Access токен тип JWT, алгоритм SHA512, хранить в базе строго запрещено.

Refresh токен тип произвольный, формат передачи base64, хранится в базе исключительно в виде bcrypt хеша, должен быть защищен от изменения на стороне клиента и попыток повторного использования.

Access, Refresh токены обоюдно связаны, Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.

Payload токенов должен содержать сведения об ip адресе клиента, которому он был выдан. В случае, если ip адрес изменился, при рефреш операции нужно послать email warning на почту юзера (для упрощения можно использовать моковые данные).
