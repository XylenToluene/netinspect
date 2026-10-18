# Общие правила для веб-интерфейса netinspect (подключается через include
# внутри server { }). Каталог root заполняется командой:
#   python -m netinspect graph ... --web-dir <root>

index index.html;
charset utf-8;
charset_types text/css application/javascript application/json;
autoindex off;
server_tokens off;

# Интерфейс статический, весь JS/CSS — из своих файлов: строгий CSP.
add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer" always;

gzip on;
gzip_types text/css application/javascript application/json image/svg+xml;
gzip_min_length 1024;

# Только чтение.
if ($request_method !~ ^(GET|HEAD)$) {
    return 405;
}

# Временные файлы атомарной записи (.tmp-*) и прочие скрытые файлы.
location ~ /\. {
    deny all;
}

# Данные графа и UI обновляются при каждой выгрузке — всегда перепроверять.
location = /graph.json {
    expires -1;
    try_files $uri =404;
}

location / {
    expires -1;
    try_files $uri $uri/ =404;
}
