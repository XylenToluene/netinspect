# Общие правила веб-интерфейса netinspect (подключается через include внутри server { }).
# Статика: index.html (подключение), graph.html (граф), *.js, *.css.
# API: /api/ проксируется на бэкенд `python -m netinspect serve` (127.0.0.1:8081).

index index.html;
charset utf-8;
charset_types text/css application/javascript application/json;
autoindex off;
server_tokens off;

# Весь JS/CSS — из своих файлов: строгий CSP.
add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer" always;

gzip on;
gzip_types text/css application/javascript application/json image/svg+xml;  # woff2 уже сжат
gzip_min_length 1024;

# Скрытые файлы, в т.ч. временные файлы атомарной записи (.tmp-*).
location ~ /\. {
    deny all;
}

# JSON API бэкенда. Тело запроса /api/connect содержит токен — не логируйте его
# (nginx по умолчанию тела не пишет; не добавляйте $request_body в log_format).
location /api/ {
    proxy_pass http://127.0.0.1:8081;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Connection "";
    proxy_read_timeout 120s;      # проверка подключения делает десятки запросов к API
    client_max_body_size 512k;    # CA-бандл
    proxy_buffering off;
}

# Шрифты (ui/static/fonts) не меняются — кэшируем на неделю.
location /fonts/ {
    limit_except GET { deny all; }
    expires 7d;
    try_files $uri =404;
}

# Статика: только чтение, всегда перепроверять (обновляется при выгрузке).
location / {
    limit_except GET { deny all; }
    expires -1;
    try_files $uri $uri/ =404;
}
